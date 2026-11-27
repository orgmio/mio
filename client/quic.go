package client

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/quic-go"

	"github.com/orgmio/mio/protocol"
	"github.com/orgmio/mio/protocol/congestion"
	"github.com/orgmio/mio/protocol/quicauth"
)

const (
	quicDialTimeout = 5 * time.Second
	replyTimeout    = 10 * time.Second
)

// quicSession 是到服务端的一条长连接，每个代理连接占用其上的一个 stream。
type quicSession struct {
	conn      *quic.Conn
	transport *quic.Transport
	udp       *net.UDPConn
	closeOnce sync.Once
	early     earlySupport
}

// emptyConnID 让客户端使用零长度源连接 ID，与 Chrome 一致。
type emptyConnID struct{}

func (emptyConnID) GenerateConnectionID() (quic.ConnectionID, error) {
	return quic.ConnectionIDFromBytes(nil), nil
}

func (emptyConnID) ConnectionIDLen() int { return 0 }

// quicClientConfig 的窗口、流数量、空闲超时和初始包大小取接近 Chrome 的值。
func quicClientConfig(ipv4 bool) *quic.Config {
	size := uint16(1232)
	if ipv4 {
		size = 1252
	}
	return &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     8 << 20,
		MaxStreamReceiveWindow:         32 << 20,
		InitialConnectionReceiveWindow: 16 << 20,
		MaxConnectionReceiveWindow:     64 << 20,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          103,
		InitialPacketSize:              size,
	}
}

func dialQUIC(ctx context.Context, peer protocol.Peer) (_ *quicSession, err error) {
	address := net.JoinHostPort(peer.Server, strconv.Itoa(peer.ServerPort))
	started := time.Now()

	slog.InfoContext(ctx, "outbound/mio: QUIC (UDP) dialing", "peer", address)
	defer func() {
		if err == nil {
			return
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			slog.InfoContext(ctx, "outbound/mio: QUIC dial canceled", "peer", address, "elapsed", time.Since(started))
			return
		}
		slog.WarnContext(ctx, "outbound/mio: QUIC dial failed", "peer", address, "elapsed", time.Since(started), "err", err)
	}()
	dialCtx, cancel := context.WithTimeout(ctx, quicDialTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(dialCtx, peer.Server)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no IP address for QUIC peer")
	}
	// 首选第一个 IPv4，其他地址按解析顺序回退。
	for i, candidate := range addrs {
		if candidate.IP.To4() != nil {
			copy(addrs[1:i+1], addrs[:i])
			addrs[0] = candidate
			break
		}
	}
	deadline, _ := dialCtx.Deadline()
	var failures error
	for i, ip := range addrs {
		if err := dialCtx.Err(); err != nil {
			return nil, errors.Join(failures, err)
		}
		// 每次只占用剩余预算的一份，避免无响应的地址耗尽整个拨号时限。
		attempt, stop := context.WithTimeout(dialCtx, time.Until(deadline)/time.Duration(len(addrs)-i))
		session, err := dialQUICAddress(attempt, peer, ip)
		stop()
		if err == nil {
			return session, nil
		}
		failures = errors.Join(failures, fmt.Errorf("%s: %w", ip.String(), err))
	}
	return nil, failures
}

func dialQUICAddress(ctx context.Context, peer protocol.Peer, ip net.IPAddr) (*quicSession, error) {
	addr := &net.UDPAddr{IP: ip.IP, Port: peer.ServerPort, Zone: ip.Zone}
	network := "udp6"
	if ip.IP.To4() != nil {
		network = "udp4"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	marker, err := quicauth.NewMarker(peer.PublicKey)
	if err != nil {
		udp.Close()
		return nil, err
	}

	transport := &quic.Transport{Conn: udp, ConnectionIDGenerator: emptyConnID{}}
	tlsConf := &tls.Config{
		ServerName: peer.Dest,
		NextProtos: []string{"h3"},
		MinVersion: tls.VersionTLS13,
		// 服务端证书是自签的，对端身份由 authenticate 里绑定通道的 HMAC 校验。
		InsecureSkipVerify: true,
		Rand:               quicauth.NewRand(marker),
	}
	conn, err := transport.Dial(ctx, addr, tlsConf, quicClientConfig(addr.IP.To4() != nil))
	if err != nil {
		transport.Close()
		udp.Close()
		return nil, fmt.Errorf("quic handshake: %w", err)
	}

	slog.InfoContext(ctx, "outbound/mio: QUIC handshake complete, starting mio authentication", "peer", addr.String())
	congestion.UseBBR(conn)
	session := &quicSession{conn: conn, transport: transport, udp: udp}
	if err := session.authenticate(ctx, peer.PublicKey); err != nil {
		session.Close()
		return nil, fmt.Errorf("quic auth failed (wrong public key, or incompatible with local mio protocol %s): %w", protocol.Version, err)
	}
	context.AfterFunc(conn.Context(), session.Close)
	slog.InfoContext(ctx, "outbound/mio: QUIC mio session ready", "peer", addr.String())
	return session, nil
}

// authenticate 在首条流 上交换绑定 TLS 导出密钥的 HMAC，服务端证明持有私钥，客户端证明知道公钥。
func (s *quicSession) authenticate(parent context.Context, server *ecdh.PublicKey) error {
	state := s.conn.ConnectionState()
	exporter, err := state.TLS.ExportKeyingMaterial(quicauth.ExporterLabel, nil, 32)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, quicauth.Timeout)
	defer cancel()
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	deadline, _ := ctx.Deadline()
	stream.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()

	message, expected, err := quicauth.ClientAuth(server, exporter)
	if err != nil {
		return err
	}
	if _, err := stream.Write(message); err != nil {
		return err
	}
	reply := make([]byte, quicauth.ServerMessageSize)
	if _, err := io.ReadFull(stream, reply); err != nil {
		return err
	}
	if !hmac.Equal(reply, expected) {
		return fmt.Errorf("server proof mismatch")
	}
	// 服务端读完就会 STOP_SENDING，此时 Close 可能报已取消，认证本身已经成功。
	stream.Close()
	return nil
}

func (s *quicSession) dialStream(ctx context.Context, request protocol.StreamRequest) (net.Conn, error) {
	return s.openStream(ctx, request, false)
}

func (s *quicSession) openStream(ctx context.Context, request protocol.StreamRequest, early bool) (net.Conn, error) {
	var stream *quic.Stream
	var err error
	if early {
		stream, err = s.conn.OpenStream()
	} else {
		stream, err = s.conn.OpenStreamSync(ctx)
	}
	if err != nil {
		return nil, err
	}
	conn := protocol.NewStreamConn(stream, func() { stream.CancelRead(0) }, s.conn.LocalAddr(), s.conn.RemoteAddr())
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	})
	defer stop()
	deadline := time.Now().Add(replyTimeout)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	conn.SetDeadline(deadline)
	err = request.Write(conn)
	if err == nil && !early {
		err = protocol.ReadReply(conn)
	}
	if !stop() || ctx.Err() != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (s *quicSession) Close() {
	s.closeOnce.Do(func() {
		s.conn.CloseWithError(0, "")
		s.transport.Close()
		s.udp.Close()
	})
}

package protocol

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/apernet/quic-go"

	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/internal/congestion"
)

const quicDialTimeout = 5 * time.Second

// quicSession 是到服务端的一条长连接，每个代理连接占用其上的一个 stream。
type quicSession struct {
	conn      *quic.Conn
	transport *quic.Transport
	udp       *net.UDPConn
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
		InitialStreamReceiveWindow:     6 << 20,
		MaxStreamReceiveWindow:         16 << 20,
		InitialConnectionReceiveWindow: 15 << 20,
		MaxConnectionReceiveWindow:     32 << 20,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          103,
		InitialPacketSize:              size,
	}
}

func dialQUIC(ctx context.Context, peer config.Peer) (*quicSession, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(peer.Server, strconv.Itoa(peer.Port)))
	if err != nil {
		return nil, err
	}
	network := "udp6"
	if addr.IP.To4() != nil {
		network = "udp4"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	marker, err := NewQUICMarker(peer.Password)
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
		Rand:               &markerRand{marker: marker},
	}
	dialCtx, cancel := context.WithTimeout(ctx, quicDialTimeout)
	defer cancel()
	conn, err := transport.Dial(dialCtx, addr, tlsConf, quicClientConfig(addr.IP.To4() != nil))
	if err != nil {
		transport.Close()
		udp.Close()
		return nil, fmt.Errorf("quic handshake: %w", err)
	}
	congestion.UseBBR(conn)

	session := &quicSession{conn: conn, transport: transport, udp: udp}
	if err := session.authenticate(peer.Password); err != nil {
		session.Close()
		return nil, fmt.Errorf("quic auth: %w", err)
	}
	return session, nil
}

// authenticate 在首个 stream 上交换绑定 TLS 导出密钥的 HMAC，双方都证明持有密码。
func (s *quicSession) authenticate(password string) error {
	state := s.conn.ConnectionState()
	exporter, err := state.TLS.ExportKeyingMaterial(QUICExporterLabel, nil, 32)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), QUICAuthTimeout)
	defer cancel()
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	stream.SetDeadline(time.Now().Add(QUICAuthTimeout))

	if _, err := stream.Write(QUICProof(password, QUICClientLabel, exporter)); err != nil {
		return err
	}
	reply := make([]byte, 32)
	if _, err := io.ReadFull(stream, reply); err != nil {
		return err
	}
	if !hmac.Equal(reply, QUICProof(password, QUICServerLabel, exporter)) {
		return fmt.Errorf("server proof mismatch")
	}
	// 服务端读完就会 STOP_SENDING，此时 Close 可能报已取消，认证本身已经成功。
	stream.Close()
	return nil
}

func (s *quicSession) dialStream(ctx context.Context, target string) (net.Conn, error) {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	conn := NewStreamConn(stream, func() { stream.CancelRead(0) }, s.conn.LocalAddr(), s.conn.RemoteAddr())
	if err := WriteRequest(conn, target); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Now().Add(replyTimeout))
	if err := ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})
	return conn, nil
}

func (s *quicSession) done() <-chan struct{} { return s.conn.Context().Done() }

func (s *quicSession) Close() {
	s.conn.CloseWithError(0, "")
	s.transport.Close()
	s.udp.Close()
}

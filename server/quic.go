package server

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/apernet/quic-go"

	"github.com/orgmio/mio/protocol"
)

// runQUIC 在与 TCP 相同的端口上监听 UDP：带有效标记的流量由 quic-go 处理，其余转发给真站。
func (s *Server) runQUIC(ctx context.Context) error {
	address := net.JoinHostPort(s.cfg.Listen, strconv.Itoa(s.cfg.Port))
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	sock, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	cert, err := selfSignedCert(s.cfg.Dest)
	if err != nil {
		sock.Close()
		return err
	}

	dest, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.cfg.Dest, strconv.Itoa(s.cfg.DestPort)))
	if err != nil {
		slog.Warn("resolve dest udp failed, unmarked quic traffic will be dropped", "err", err)
		dest = nil
	}
	d := newDemux(sock, s.cfg.Password, dest)
	go d.run(ctx)

	transport := &quic.Transport{Conn: d.virtual}
	listener, err := transport.Listen(&tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{
		MaxIdleTimeout:                 60 * time.Second,
		InitialStreamReceiveWindow:     6 << 20,
		MaxStreamReceiveWindow:         16 << 20,
		InitialConnectionReceiveWindow: 15 << 20,
		MaxConnectionReceiveWindow:     32 << 20,
		MaxIncomingStreams:             1024,
	})
	if err != nil {
		sock.Close()
		return err
	}
	slog.Info("Listen mio quic", "address", sock.LocalAddr().String())

	go func() {
		<-ctx.Done()
		listener.Close()
		transport.Close()
	}()
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveQUIC(ctx, conn)
	}
}

func (s *Server) serveQUIC(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "")
	if err := s.authQUIC(ctx, conn); err != nil {
		slog.Debug("quic auth failed", "from", conn.RemoteAddr().String(), "err", err)
		return
	}
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		client := protocol.NewStreamConn(stream, func() { stream.CancelRead(0) }, conn.LocalAddr(), conn.RemoteAddr())
		go s.proxy(ctx, client)
	}
}

// authQUIC 校验客户端在首个 stream 上发来的、绑定 TLS 导出密钥的 HMAC，并回送服务端的证明。
func (s *Server) authQUIC(ctx context.Context, conn *quic.Conn) error {
	authCtx, cancel := context.WithTimeout(ctx, protocol.QUICAuthTimeout)
	defer cancel()
	stream, err := conn.AcceptStream(authCtx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	stream.SetDeadline(time.Now().Add(protocol.QUICAuthTimeout))

	got := make([]byte, 32)
	if _, err := io.ReadFull(stream, got); err != nil {
		return err
	}
	state := conn.ConnectionState()
	exporter, err := state.TLS.ExportKeyingMaterial(protocol.QUICExporterLabel, nil, 32)
	if err != nil {
		return err
	}
	if !hmac.Equal(got, protocol.QUICProof(s.cfg.Password, protocol.QUICClientLabel, exporter)) {
		return io.ErrUnexpectedEOF
	}
	if _, err := stream.Write(protocol.QUICProof(s.cfg.Password, protocol.QUICServerLabel, exporter)); err != nil {
		return err
	}
	return stream.Close()
}

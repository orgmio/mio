package server

import (
	"context"
	"crypto/tls"
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

// startQUIC 在与 TCP 相同的端口上监听 UDP：带有效标记的流量由 quic-go 处理，其余转发给真站。
// 监听成功后返回接受连接的循环，由调用方运行，直到 ctx 结束。
func (s *Server) startQUIC(ctx context.Context) (func() error, error) {
	address := net.JoinHostPort(s.cfg.Listen, strconv.Itoa(s.cfg.ListenPort))
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	sock, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	cert, err := selfSignedCert(s.cfg.Dest)
	if err != nil {
		sock.Close()
		return nil, err
	}

	d := newDemux(sock, s.key.PublicKey(), net.JoinHostPort(s.cfg.Dest, strconv.Itoa(s.cfg.DestPort)))

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
		return nil, err
	}
	slog.Info("inbound/mio: udp server started at " + sock.LocalAddr().String())

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	demuxDone := make(chan struct{})
	go func() {
		defer close(demuxDone)
		d.run(ctx)
	}()
	go func() {
		<-ctx.Done()
		sock.Close()
		d.virtual.Close()
		listener.Close()
		transport.Close()
		<-demuxDone
		close(done)
	}()
	s.closeQUIC = func() {
		cancel()
		<-done
	}
	return func() error {
		var clients sync.WaitGroup
		defer clients.Wait()
		defer cancel()
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			clients.Go(func() { s.handleQUIC(ctx, conn) })
		}
	}, nil
}

func (s *Server) handleQUIC(ctx context.Context, conn *quic.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	var streams sync.WaitGroup
	defer streams.Wait()
	defer cancel()
	defer conn.CloseWithError(0, "")
	congestion.UseBBR(conn)
	if err := s.authQUIC(ctx, conn); err != nil {
		slog.Debug("inbound/mio: quic auth from "+conn.RemoteAddr().String(), "err", err)
		return
	}
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		client := protocol.NewStreamConn(stream, func() { stream.CancelRead(0) }, conn.LocalAddr(), conn.RemoteAddr())
		streams.Go(func() { s.proxy(ctx, client) })
	}
}

// authQUIC 校验客户端在首条流 上发来的临时公钥与证明（绑定 TLS 导出密钥），并回送只有持有私钥才能算出的服务端证明。
func (s *Server) authQUIC(ctx context.Context, conn *quic.Conn) error {
	authCtx, cancel := context.WithTimeout(ctx, quicauth.Timeout)
	defer cancel()
	stream, err := conn.AcceptStream(authCtx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	stream.SetDeadline(time.Now().Add(quicauth.Timeout))

	got := make([]byte, quicauth.ClientMessageSize)
	if _, err := io.ReadFull(stream, got); err != nil {
		return err
	}
	state := conn.ConnectionState()
	exporter, err := state.TLS.ExportKeyingMaterial(quicauth.ExporterLabel, nil, 32)
	if err != nil {
		return err
	}
	reply, err := quicauth.ServerAuth(s.key, exporter, got)
	if err != nil {
		return err
	}
	if _, err := stream.Write(reply); err != nil {
		return err
	}
	return stream.Close()
}

package server

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/orgmio/mio/config"
)

const (
	dialTimeout    = 5 * time.Second
	requestTimeout = 10 * time.Second
)

// Server 把所有连接当作普通访问转发给真站，只有握手后发来正确认证记录的客户端才会被接管并代理。
type Server struct {
	cfg config.Inbound
}

func New(cfg config.Inbound) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Run(ctx context.Context) error {
	address := net.JoinHostPort(s.cfg.Listen, strconv.Itoa(s.cfg.ListenPort))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	slog.Info("Listen mio server", "address", listener.Addr().String())

	go func() {
		if err := s.runQUIC(ctx); err != nil {
			slog.Warn("quic disabled", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serve(ctx, conn)
	}
}

func (s *Server) serve(ctx context.Context, client net.Conn) {
	destAddress := net.JoinHostPort(s.cfg.Dest, strconv.Itoa(s.cfg.DestPort))
	dialer := net.Dialer{Timeout: dialTimeout}
	dest, err := dialer.DialContext(ctx, "tcp", destAddress)
	if err != nil {
		slog.Warn("dial dest failed", "dest", destAddress, "err", err)
		client.Close()
		return
	}

	conn, ok := s.relay(client, dest)
	if !ok {
		slog.Debug("connection ended without authentication", "from", client.RemoteAddr().String())
		client.Close()
		return
	}
	s.proxy(ctx, conn)
}

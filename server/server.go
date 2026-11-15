package server

import (
	"context"
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/protocol"
)

const (
	dialTimeout    = 5 * time.Second
	requestTimeout = 10 * time.Second
)

// Server 把所有连接当作普通访问转发给真站，只有握手后发来正确认证记录的客户端才会被接管并代理。
type Server struct {
	cfg config.Inbound
	key *ecdh.PrivateKey

	listener  net.Listener
	serveQUIC func() error // 为 nil 表示 QUIC 没有启动成功
}

func New(cfg config.Inbound) (*Server, error) {
	key, err := protocol.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, key: key}, nil
}

// Run 开始监听并处理连接，直到 ctx 结束。等同于先 Start 再 Serve。
func (s *Server) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}
	return s.Serve(ctx)
}

// Start 开始监听 TCP 和 UDP。TCP 监听失败会返回错误；UDP（QUIC）监听失败只记一条警告，服务端仍可只用 TCP 工作。
func (s *Server) Start(ctx context.Context) error {
	address := net.JoinHostPort(s.cfg.Listen, strconv.Itoa(s.cfg.ListenPort))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	s.listener = listener
	slog.Info("inbound/mio: tcp server started at " + listener.Addr().String())

	serveQUIC, err := s.startQUIC(ctx)
	if err != nil {
		slog.Warn("inbound/mio: quic disabled", "err", err)
	}
	s.serveQUIC = serveQUIC
	return nil
}

// Serve 处理 Start 之后到来的连接，直到 ctx 结束。必须先调用 Start。
func (s *Server) Serve(ctx context.Context) error {
	listener := s.listener
	if listener == nil {
		return errors.New("server is not started")
	}
	if s.serveQUIC != nil {
		go func() {
			if err := s.serveQUIC(); err != nil {
				slog.Warn("inbound/mio: quic disabled", "err", err)
			}
		}()
	}
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
		slog.Error("inbound/mio: open connection to dest "+destAddress, "err", err)
		client.Close()
		return
	}

	conn, ok := s.relay(client, dest)
	if !ok {
		slog.Debug("inbound/mio: connection from " + client.RemoteAddr().String() + " ended without authentication")
		client.Close()
		return
	}
	s.proxy(ctx, conn)
}

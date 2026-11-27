package server

import (
	"context"
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
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
	closeQUIC func()
	serveQUIC func() error // 为 nil 表示 QUIC 没有启动成功
}

func New(cfg config.Inbound) (*Server, error) {
	key, err := protocol.ParsePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	// dest_port 没填时，转发到伪装站上与监听端口相同的端口。
	if cfg.DestPort == 0 {
		cfg.DestPort = cfg.ListenPort
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

// Start 按 transport 打开监听端口。自动模式下 UDP 不可用时继续提供 TCP。
func (s *Server) Start(ctx context.Context) error {
	if s.cfg.Transport != config.TransportUDP {
		address := net.JoinHostPort(s.cfg.Listen, strconv.Itoa(s.cfg.ListenPort))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		s.listener = listener
		slog.Info("inbound/mio: tcp server started at " + listener.Addr().String())
	}
	if s.cfg.Transport == config.TransportTCP {
		return nil
	}
	serveQUIC, err := s.startQUIC(ctx)
	if err != nil {
		if s.cfg.Transport == config.TransportUDP {
			return err
		}
		slog.Warn("inbound/mio: quic disabled", "err", err)
	}
	s.serveQUIC = serveQUIC
	return nil
}

// Close 释放 Start 打开的监听端口。
func (s *Server) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
	if s.closeQUIC != nil {
		s.closeQUIC()
	}
}

// Serve 处理 Start 之后到来的连接，直到 ctx 结束。必须先调用 Start。
func (s *Server) Serve(ctx context.Context) error {
	listener := s.listener
	if listener == nil && s.serveQUIC == nil {
		return errors.New("server is not started")
	}
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		s.Close()
		workers.Wait()
	}()
	if listener == nil {
		stop := context.AfterFunc(ctx, s.closeQUIC)
		defer stop()
		return s.serveQUIC()
	}
	if s.serveQUIC != nil {
		workers.Go(func() {
			if err := s.serveQUIC(); err != nil {
				slog.Warn("inbound/mio: quic disabled", "err", err)
			}
		})
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		workers.Go(func() { s.serve(ctx, conn) })
	}
}

func (s *Server) serve(ctx context.Context, client net.Conn) {
	defer client.Close()
	destAddress := net.JoinHostPort(s.cfg.Dest, strconv.Itoa(s.cfg.DestPort))
	dialer := net.Dialer{Timeout: dialTimeout}
	dest, err := dialer.DialContext(ctx, "tcp", destAddress)
	if err != nil {
		slog.Error("inbound/mio: open connection to dest "+destAddress, "err", err)
		return
	}

	stopRelay := context.AfterFunc(ctx, func() {
		client.Close()
		dest.Close()
	})
	session, ok := s.relay(client, dest)
	stopRelay()
	if !ok {
		slog.Debug("inbound/mio: connection from " + client.RemoteAddr().String() + " ended without authentication")
		return
	}
	// 一条认证过的连接上可以有多条流，每条流是一个代理请求。
	ctx, cancel := context.WithCancel(ctx)
	var streams sync.WaitGroup
	defer streams.Wait()
	defer cancel()
	stop := context.AfterFunc(ctx, func() { session.Close() })
	defer stop()
	defer session.Close()
	for {
		stream, err := session.Accept()
		if err != nil {
			return
		}
		streams.Go(func() { s.proxy(ctx, stream) })
	}
}

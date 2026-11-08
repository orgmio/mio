package protocol

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/orgmio/mio/config"
)

// Server 把所有连接当作普通访问转发给真站，只有握手后发来正确认证记录的客户端才会被接管。
type Server struct {
	cfg    config.Listen
	handle func(ctx context.Context, conn net.Conn)
}

// NewServer 的 handle 接管认证成功的连接并负责关闭；为 nil 时只记录日志并关闭。
func NewServer(cfg config.Listen, handle func(ctx context.Context, conn net.Conn)) *Server {
	if handle == nil {
		handle = func(_ context.Context, conn net.Conn) {
			slog.Info("authenticated client", "from", conn.RemoteAddr().String())
			conn.Close()
		}
	}
	return &Server{cfg: cfg, handle: handle}
}

func (s *Server) Run(ctx context.Context) error {
	address := net.JoinHostPort(s.cfg.Listen, strconv.Itoa(s.cfg.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	slog.Info("Listen mio server", "address", listener.Addr().String())

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
	s.handle(ctx, conn)
}

// relay 在客户端与真站之间转发 TLS 记录，直到客户端发来合法的认证记录。
func (s *Server) relay(client, dest net.Conn) (net.Conn, bool) {
	clientReader := bufio.NewReader(client)
	var serverRandom atomic.Pointer[[]byte]
	var authenticated atomic.Bool

	done := make(chan struct{})
	go func() {
		defer close(done)
		copyRecords(client, bufio.NewReader(dest), func(header, body []byte) bool {
			// 遇到 HelloRetryRequest 时会有两条 ServerHello，以最后一条为准。
			if header[0] == recordHandshake && len(body) >= 38 && body[0] == handshakeServerHello {
				random := bytes.Clone(body[6:38])
				serverRandom.Store(&random)
			}
			return false
		})
		if !authenticated.Load() {
			client.Close()
		}
	}()

	err := copyRecords(dest, clientReader, func(header, body []byte) bool {
		random := serverRandom.Load()
		return random != nil && header[0] == recordAppData && verifyAuth(s.cfg.Password, *random, body)
	})

	if errors.Is(err, errAuthenticated) {
		authenticated.Store(true)
		dest.Close()
		<-done // 等真站方向的转发彻底停止，避免之后与上层写入交错
		return &bufferedConn{Conn: client, reader: clientReader}, true
	}
	dest.Close()
	<-done
	return nil, false
}

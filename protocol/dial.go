package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	dialTimeout  = 5 * time.Second
	replyTimeout = 10 * time.Second
)

// DialSession 连接 peer 并完成握手与认证，返回的会话上可以用 Dial 打开多条到不同目标的连接。
func DialSession(ctx context.Context, peer Peer) (*Session, error) {
	address := net.JoinHostPort(peer.Server, strconv.Itoa(peer.ServerPort))
	dialer := net.Dialer{Timeout: dialTimeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to peer %s: %w", address, err)
	}
	session, err := Handshake(ctx, conn, peer)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer %s: %w", address, err)
	}
	return session, nil
}

// Dial 在会话上打开一条流，请求服务端连接 target（host:port）。服务端连不上目标时返回 ErrConnectFailed，会话仍可继续使用。
func (s *Session) Dial(ctx context.Context, target string) (net.Conn, error) {
	address := s.RemoteAddr().String()
	conn, err := s.Open()
	if err != nil {
		return nil, fmt.Errorf("peer %s: %w", address, err)
	}
	// ctx 结束时关闭这条流，让等待中的读写立刻返回。
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	conn.(*stream).SetNextPadding(16, 512)
	started := time.Now()
	if err := WriteRequest(conn, target); err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer %s: send request: %w", address, err)
	}
	conn.SetReadDeadline(time.Now().Add(replyTimeout))
	if err := ReadReply(conn); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// 服务端总会在 replyTimeout 之内应答。等到超时，而且这段时间整条连接上什么都没收到，
		// 说明连接已经悄悄断了（换了网络、休眠后唤醒），关掉它，免得后面的请求继续往上面发。
		if errors.Is(err, os.ErrDeadlineExceeded) && s.lastRecv.Load() < started.UnixNano() {
			s.closeWithError(errors.New("no response from peer"))
		}
		return nil, fmt.Errorf("peer %s: %w", address, err)
	}
	conn.SetReadDeadline(time.Time{})
	return conn, nil
}

// DialTCP 是客户端的 TCP 路径：连接 peer 完成握手与认证，请求服务端连接 target（host:port），返回的连接上的数据已由 mio 加密。
// 每次调用都会新建一条到 peer 的连接；需要在一条连接上复用多个目标时，改用 DialSession 和 Session.Dial。
func DialTCP(ctx context.Context, peer Peer, target string) (net.Conn, error) {
	session, err := DialSession(ctx, peer)
	if err != nil {
		return nil, err
	}
	conn, err := session.Dial(ctx, target)
	if err != nil {
		session.Close()
		return nil, err
	}
	return &sessionConn{Conn: conn, session: session}, nil
}

// sessionConn 是独占一个会话的流，关闭时连同会话一起关闭。
type sessionConn struct {
	net.Conn
	session *Session
}

func (c *sessionConn) ReadFrom(r io.Reader) (int64, error) {
	return c.Conn.(*stream).ReadFrom(r)
}

func (c *sessionConn) CloseWrite() error {
	return c.Conn.(*stream).CloseWrite()
}

func (c *sessionConn) Close() error {
	err := c.Conn.Close()
	c.session.Close()
	return err
}

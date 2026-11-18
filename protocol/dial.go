package protocol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	dialTimeout = 5 * time.Second
	// handshakeTimeout 是建立 TCP 连接加上 TLS 握手的总时限。调用方的 ctx 可能永远不会结束，
	// 没有它的话，对端接受 TCP 却不回 TLS 时握手会一直卡住。
	handshakeTimeout = 10 * time.Second
	replyTimeout     = 10 * time.Second
)

// DialSession 连接 peer 并完成握手与认证，返回的会话上可以用 Dial 打开多条到不同目标的连接。
func DialSession(ctx context.Context, peer Peer) (*Session, error) {
	address := net.JoinHostPort(peer.Server, strconv.Itoa(peer.ServerPort))
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
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

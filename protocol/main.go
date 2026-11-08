package protocol

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/orgmio/mio/config"
)

const (
	dialTimeout  = 5 * time.Second
	replyTimeout = 10 * time.Second
)

// DialTCP 连接 peer 完成握手与认证，请求服务端连接 target（host:port），返回的连接上的数据已由 mio 加密。
func DialTCP(ctx context.Context, peer config.Peer, target string) (net.Conn, error) {
	address := net.JoinHostPort(peer.Server, strconv.Itoa(peer.Port))
	dialer := net.Dialer{Timeout: dialTimeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("Cannot connection to peer %s: %w", address, err)
	}
	secure, err := Handshake(ctx, conn, peer)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer %s: %w", address, err)
	}
	if err := WriteRequest(secure, target); err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer %s: send request: %w", address, err)
	}
	conn.SetReadDeadline(time.Now().Add(replyTimeout))
	if err := ReadReply(secure); err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer %s: %w", address, err)
	}
	conn.SetReadDeadline(time.Time{})
	return secure, nil
}

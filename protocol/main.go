package protocol

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/orgmio/mio/config"
)

const dialTimeout = 5 * time.Second

// Dial 连接 peer 并完成握手与认证，返回的连接上的传输协议尚未定义。
func Dial(ctx context.Context, peer config.Peer) (net.Conn, error) {
	address := net.JoinHostPort(peer.Server, strconv.Itoa(peer.Port))
	dialer := net.Dialer{Timeout: dialTimeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("Cannot connection to peer %s: %w", address, err)
	}
	if err := Handshake(ctx, conn, peer); err != nil {
		conn.Close()
		return nil, fmt.Errorf("peer %s: %w", address, err)
	}
	return conn, nil
}

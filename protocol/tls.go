package protocol

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/orgmio/mio/config"
)

// Handshake 经服务端中转与真站完成 TLS 握手，向真站发出 close_notify，再向服务端发送认证记录。
func Handshake(ctx context.Context, raw net.Conn, peer config.Peer) error {
	conn := utls.UClient(raw, &utls.Config{ServerName: peer.Dest}, utls.HelloChrome_Auto)
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	// 只关闭 TLS 写端，不能关底层 TCP，后面还要用它发认证记录。
	if err := conn.CloseWrite(); err != nil {
		return fmt.Errorf("send close_notify: %w", err)
	}
	// CloseWrite 会把底层连接的写超时设成"现在"，不清除的话后面的写入必然超时。
	if err := raw.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	if _, err := raw.Write(authRecord(peer.Password, conn.HandshakeState.ServerHello.Random)); err != nil {
		return fmt.Errorf("send auth record: %w", err)
	}
	return nil
}

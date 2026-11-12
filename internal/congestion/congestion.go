// Package congestion 为 mio 的 QUIC 连接提供拥塞控制，BBR 实现来自 Hysteria2。
package congestion

import (
	"github.com/apernet/quic-go"

	"github.com/orgmio/mio/internal/congestion/bbr"
)

// UseBBR 在 QUIC 握手完成后为 conn 安装 BBR 拥塞控制器。
func UseBBR(conn *quic.Conn) {
	conn.SetCongestionControl(bbr.NewBbrSender(bbr.DefaultClock{}, conn.InitialPacketSize()))
}

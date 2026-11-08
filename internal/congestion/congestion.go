package congestion

import (
	"github.com/apernet/quic-go"

	"github.com/orgmio/mio/internal/congestion/bbr"
)

// UseBBR 用 BBR 替换默认的 Cubic；种子包大小不能超过 QUIC 自身的起始值，否则首次 MTU 探测会被当成缩小。
func UseBBR(conn *quic.Conn) {
	size := bbr.GetInitialPacketSize(conn.RemoteAddr())
	if initial := conn.InitialPacketSize(); initial > 0 {
		size = min(initial, size)
	}
	conn.SetCongestionControl(bbr.NewBbrSender(bbr.DefaultClock{}, size, bbr.ProfileStandard))
}

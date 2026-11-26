package bbr

import (
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
)

const (
	infBandwidth = Bandwidth(math.MaxUint64)
)

// Bandwidth 表示连接的带宽。
type Bandwidth uint64

const (
	// BitsPerSecond 表示每秒 1 比特。
	BitsPerSecond Bandwidth = 1
	// BytesPerSecond 表示每秒 1 字节。
	BytesPerSecond = 8 * BitsPerSecond
)

// BandwidthFromDelta 根据字节数和时间间隔计算带宽。
func BandwidthFromDelta(bytes congestion.ByteCount, delta time.Duration) Bandwidth {
	return Bandwidth(bytes) * Bandwidth(time.Second) / Bandwidth(delta) * BytesPerSecond
}

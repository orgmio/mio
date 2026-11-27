package bbr

import "github.com/apernet/quic-go/monotime"

// Clock 返回当前时间。
type Clock interface {
	Now() monotime.Time
}

// DefaultClock 使用 Go 标准库时钟实现 Clock 接口。
type DefaultClock struct{}

var _ Clock = DefaultClock{}

// Now 获取当前时间。
func (DefaultClock) Now() monotime.Time {
	return monotime.Now()
}

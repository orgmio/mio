package common

import (
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	maxBurstPackets               = 10
	maxBurstPacingDelayMultiplier = 4
)

// Pacer 实现令牌桶 pacing 算法。
type Pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() congestion.ByteCount // 单位为 bytes/s
}

func NewPacer(getBandwidth func() congestion.ByteCount) *Pacer {
	p := &Pacer{
		budgetAtLastSent: maxBurstPackets * congestion.InitialPacketSize,
		maxDatagramSize:  congestion.InitialPacketSize,
		getBandwidth:     getBandwidth,
	}
	return p
}

func (p *Pacer) SentPacket(sendTime monotime.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *Pacer) Budget(now monotime.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	budget := p.budgetAtLastSent + (p.getBandwidth()*congestion.ByteCount(now.Sub(p.lastSentTime).Nanoseconds()))/1e9
	if budget < 0 { // 防止溢出
		budget = congestion.ByteCount(1<<62 - 1)
	}
	return min(p.maxBurstSize(), budget)
}

func (p *Pacer) maxBurstSize() congestion.ByteCount {
	return max(
		congestion.ByteCount((maxBurstPacingDelayMultiplier*congestion.MinPacingDelay).Nanoseconds())*p.getBandwidth()/1e9,
		maxBurstPackets*p.maxDatagramSize,
	)
}

// TimeUntilSend 返回下一个数据包应当发送的时间。
// 如果可以立即发送数据包，则返回零值。
func (p *Pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	bw := uint64(p.getBandwidth())
	// 可能需要对该值向上取整。
	// 否则，计时器到期时的预算可能会略小于数据报大小。
	d := diff / bw
	// 这相当于 math.Ceil，但只使用整数运算。
	if diff%bw > 0 {
		d++
	}
	return p.lastSentTime.Add(max(congestion.MinPacingDelay, time.Duration(d)*time.Nanosecond))
}

func (p *Pacer) SetMaxDatagramSize(s congestion.ByteCount) {
	p.maxDatagramSize = s
}

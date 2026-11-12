package protocol

import (
	"github.com/orgmio/mio/protocol/padding"
)

// 帧放在一条 TLS Application Data 记录的密文里，解密后的明文为：
//
//	[类型 1 字节][负载长度 2 字节，大端][负载][填充]
//
// 读方遇到不认识的帧类型会跳过，因此以后可以新增帧类型而不破坏兼容。
const (
	FrameReady byte = 0 // 服务端的就绪帧，负载为服务端密钥份额
	FrameData  byte = 1 // 应用数据
	FrameClose byte = 2 // 发送方向结束（半关闭）

	FrameHeaderSize = 3
	MaxFramePayload = 16384 - 1
)

// PaddingPolicy 决定每个帧追加多少字节的随机填充。
type PaddingPolicy interface {
	// PaddingLength 返回本帧的填充长度，frameType 为帧类型，payloadLen 为负载长度，
	// dataFrames 为此前已发出的 data 帧数，limit 为本帧能容纳的最大填充长度。
	// 返回值超出 [0, limit] 时会被截断。
	PaddingLength(frameType byte, payloadLen int, dataFrames uint64, limit int) (int, error)
}

// DefaultPadding 是 mio 默认的填充策略：
// ready 帧填充 0–1024 字节；前 8 个 data 帧中，负载不足 900 字节的补到 900–1400 字节，其余填充 0–255 字节；之后不再填充。
type DefaultPadding struct{}

func (DefaultPadding) PaddingLength(frameType byte, payloadLen int, dataFrames uint64, limit int) (int, error) {
	minimum, maximum := 0, 0
	switch {
	case frameType == FrameReady:
		maximum = 1024
	case frameType == FrameData && dataFrames < 8 && payloadLen < 900:
		minimum = max(0, 900-FrameHeaderSize-payloadLen)
		maximum = max(minimum, 1400-FrameHeaderSize-payloadLen)
	case frameType == FrameData && dataFrames < 8:
		maximum = 255
	default:
		return 0, nil
	}
	minimum, maximum = min(minimum, limit), min(maximum, limit)
	return padding.RandomInt(minimum, maximum)
}

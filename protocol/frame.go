package protocol

import (
	"github.com/orgmio/mio/protocol/padding"
)

// 帧放在一条 TLS Application Data 记录的密文里，解密后的明文为：
//
//	[类型 1 字节][流编号 4 字节，大端][负载长度 2 字节，大端][负载][填充]
//
// 一条连接上可以同时有多条流，流编号由客户端分配，从 1 开始逐条加 1；ready 帧的流编号为 0。
// 读方遇到不认识的帧类型会跳过，因此以后可以新增帧类型而不破坏兼容。
const (
	FrameReady  byte = 0 // 服务端的就绪帧，负载为服务端密钥份额
	FrameData   byte = 1 // 流上的应用数据；服务端收到新编号的 data 帧即视为客户端打开了一条流
	FrameClose  byte = 2 // 发送方不再在这条流上发送数据（半关闭），负载为空
	FrameReset  byte = 3 // 发送方放弃这条流，不再读也不再写，负载为空
	FrameWindow byte = 4 // 流量控制：负载为 4 字节大端整数，表示接收方又可以多收这么多字节的 data 负载

	FrameHeaderSize = 7

	// maxRecordBody 是一条记录的密文上限，与不带填充的 TLS 1.3 实现相同：16384 字节明文 + 1 字节类型 + 16 字节 tag。
	maxRecordBody = 16384 + 1 + 16
	// MaxFramePayload 是一个帧的负载上限，正好填满一条最大的记录。
	MaxFramePayload = maxRecordBody - 16 - FrameHeaderSize

	// StreamWindow 是每条流、每个方向的初始接收窗口：未被 window 帧追加额度前，对端最多发送这么多字节的 data 负载。
	StreamWindow = 4 << 20
)

// PaddingPolicy 决定每个帧追加多少字节的随机填充。
type PaddingPolicy interface {
	// PaddingLength 返回本帧的填充长度，frameType 为帧类型，payloadLen 为负载长度，
	// dataFrames 为这条流此前已发出的 data 帧数，limit 为本帧能容纳的最大填充长度。
	// 返回值超出 [0, limit] 时会被截断。
	PaddingLength(frameType byte, payloadLen int, dataFrames uint64, limit int) (int, error)
}

// DefaultPadding 是 mio 默认的填充策略：
// ready 帧填充 0–1024 字节；每条流的前 8 个 data 帧中，负载不足 900 字节的补到 900–1400 字节，其余填充 0–255 字节；之后不再填充。
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

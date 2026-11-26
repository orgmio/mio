package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/orgmio/mio/internal/tlsrecord"
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

	// maxRecordBody 是一条记录的密文上限，与不带填充的 TLS 1.3 实现相同：16384 字节明文 + 1 字节类型 + 16 字节认证标签。
	maxRecordBody = 16384 + 1 + 16
	// MaxFramePayload 是一个帧的负载上限，正好填满一条最大的记录。
	MaxFramePayload = maxRecordBody - 16 - FrameHeaderSize

	// maxRecordsPerKey 限制每个方向的 AES-GCM 调用次数，远早于序号回绕。
	maxRecordsPerKey = 1 << 24

	// StreamWindow 是每条流、每个方向的初始接收窗口：未被 window 帧追加额度前，对端最多发送这么多字节的 data 负载。
	StreamWindow = 16 << 20
)

var errRecordLimit = errors.New("mio record key usage limit reached")

// framePadding 是每个帧的填充长度，limit 为本帧能容纳的最大填充长度：
// ready 帧填充 0–1024 字节；每条流的前 8 个 data 帧中，负载不足 900 字节的补到 900–1400 字节，其余填充 0–255 字节；之后不再填充。
func framePadding(frameType byte, payloadLen int, dataFrames uint64, limit int) int {
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
		return 0
	}
	minimum, maximum = max(0, min(minimum, limit)), max(0, min(maximum, limit))
	length, err := padding.RandomInt(minimum, maximum)
	if err != nil {
		return 0
	}
	return length
}

// paddingLength 算出一个帧的填充长度。
func (s *Session) paddingLength(typ byte, payloadLength int, dataFrames uint64) int {
	return framePadding(typ, payloadLength, dataFrames, MaxFramePayload-payloadLength)
}

// writeFrame 把一个帧封装成一条记录写出，padLength 超出记录容量的部分会被截掉。写失败时会话随之关闭。
// 记录在会话自己的缓冲里拼好后原地加密，不分配内存。填充为全零：它在密文里，外面看不到内容，只看得到长度。
func (s *Session) writeFrame(typ byte, id uint32, payload []byte, padLength int) error {
	select {
	case s.writeMu <- struct{}{}:
		defer func() { <-s.writeMu }()
	case <-s.done:
		return s.closeError()
	}
	if err := s.conn.SetWriteDeadline(time.Now().Add(sessionWriteTimeout)); err != nil {
		return err
	}
	return s.writeFrameLocked(typ, id, payload, padLength)
}

const sessionWriteTimeout = 10 * time.Second

// 调用 writeFrameLocked 前，须持有会话的写入锁并设置底层连接的写入截止时间。
func (s *Session) writeFrameLocked(typ byte, id uint32, payload []byte, padLength int) error {
	if s.sendSeq >= maxRecordsPerKey {
		s.closeWithError(errRecordLimit)
		return errRecordLimit
	}
	if len(payload) > MaxFramePayload {
		return errors.New("frame payload too large")
	}
	padLength = max(0, min(padLength, MaxFramePayload-len(payload)))
	plainSize := FrameHeaderSize + len(payload) + padLength

	overhead := s.send.Overhead()
	recordSize := tlsrecord.HeaderSize + plainSize + overhead
	if cap(s.writeBuf) < recordSize {
		s.writeBuf = make([]byte, tlsrecord.HeaderSize+FrameHeaderSize+MaxFramePayload+overhead)
	}
	record := s.writeBuf[:recordSize]
	header := record[:tlsrecord.HeaderSize]
	header[0], header[1], header[2] = tlsrecord.TypeAppData, 0x03, 0x03
	binary.BigEndian.PutUint16(header[3:], uint16(plainSize+overhead))
	plain := record[tlsrecord.HeaderSize : tlsrecord.HeaderSize+plainSize]
	plain[0] = typ
	binary.BigEndian.PutUint32(plain[1:5], id)
	binary.BigEndian.PutUint16(plain[5:FrameHeaderSize], uint16(len(payload)))
	copy(plain[FrameHeaderSize:], payload)
	clear(plain[FrameHeaderSize+len(payload):])
	s.send.Seal(plain[:0], seqNonce(&s.sendNonce, s.sendSeq), plain, header)
	s.sendSeq++
	if err := writeAll(s.conn, record); err != nil {
		s.closeWithError(err)
		return err
	}
	return nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// readFrame 读取并原地解密一条记录；返回的负载在下一次 readFrame 前有效。
// skipForeign 为 true 时跳过解不开的记录（握手期真站发来的记录）。
func (s *Session) readFrame(skipForeign bool) (typ byte, id uint32, payload []byte, err error) {
	var header [tlsrecord.HeaderSize]byte
	for {
		if _, err := io.ReadFull(s.reader, header[:]); err != nil {
			return 0, 0, nil, err
		}
		if s.recvSeq >= maxRecordsPerKey {
			return 0, 0, nil, errRecordLimit
		}
		if !tlsrecord.ValidHeader(header[:]) {
			return 0, 0, nil, errors.New("invalid record header")
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if cap(s.readBuf) < length {
			s.readBuf = make([]byte, tlsrecord.MaxBody)
		}
		body := s.readBuf[:length]
		if _, err := io.ReadFull(s.reader, body); err != nil {
			return 0, 0, nil, err
		}
		plain, err := s.recv.Open(body[:0], seqNonce(&s.recvNonce, s.recvSeq), body, header[:])
		if err != nil {
			if skipForeign {
				continue
			}
			return 0, 0, nil, errors.New("decrypt record failed")
		}
		s.recvSeq++
		s.lastRecv.Store(time.Now().UnixNano())
		if len(plain) < FrameHeaderSize {
			return 0, 0, nil, errors.New("short frame")
		}
		payloadLength := int(binary.BigEndian.Uint16(plain[5:FrameHeaderSize]))
		if payloadLength > len(plain)-FrameHeaderSize {
			return 0, 0, nil, errors.New("invalid frame payload length")
		}
		return plain[0], binary.BigEndian.Uint32(plain[1:5]), plain[FrameHeaderSize : FrameHeaderSize+payloadLength], nil
	}
}

// waitReady 等待服务端的就绪帧并返回其服务端密钥份额，之前收到的真站记录会被丢弃。
func (s *Session) waitReady() ([]byte, error) {
	typ, _, payload, err := s.readFrame(true)
	if err != nil {
		return nil, err
	}
	if typ != FrameReady {
		return nil, errors.New("unexpected frame before ready")
	}
	return append([]byte(nil), payload...), nil
}

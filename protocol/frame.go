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

	// maxWriteBatchFrames 限制单次写锁内批量封装并系统调用写出的数据帧数量，兼顾吞吐与多流公平性。
	maxWriteBatchFrames  = 4
	maxWriteBatchPayload = maxWriteBatchFrames * MaxFramePayload

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
	now := time.Now()
	if err := s.ensureWriteDeadline(now, now.Add(sessionWriteTimeout), false); err != nil {
		return err
	}
	return s.writeFrameLocked(typ, id, payload, padLength)
}

const sessionWriteTimeout = 10 * time.Second

// ensureWriteDeadline 仅在截止时间缩短或距上次设置已过半时才更新底层套接字的写入截止时间，避免每帧修改 runtime timer。
// 调用方须持有 s.writeMu（或同时持有流的锁）。
func (s *Session) ensureWriteDeadline(now, desired time.Time, hasStreamDeadline bool) error {
	if !hasStreamDeadline {
		if curNano := s.connWriteDeadline.Load(); curNano != 0 {
			cur := time.Unix(0, curNano)
			if !cur.Before(now.Add(sessionWriteTimeout/2)) && !desired.Before(cur) {
				return nil
			}
		}
	}
	if err := s.conn.SetWriteDeadline(desired); err != nil {
		s.connWriteDeadline.Store(0)
		return err
	}
	s.connWriteDeadline.Store(desired.UnixNano())
	return nil
}

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
		s.writeBuf = make([]byte, maxWriteBatchFrames*(tlsrecord.HeaderSize+FrameHeaderSize+MaxFramePayload+overhead))
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
	if padLength > 0 {
		clear(plain[FrameHeaderSize+len(payload):])
	}
	s.send.Seal(plain[:0], seqNonce(&s.sendNonce, s.sendSeq), plain, header)
	s.sendSeq++
	if err := writeAll(s.conn, record); err != nil {
		s.closeWithError(err)
		return err
	}
	return nil
}

// writeDataBatchLocked 把不超过 maxWriteBatchPayload 的数据切分成多条 data 帧，连续原地加密进 writeBuf 后一次写出。
func (s *Session) writeDataBatchLocked(id uint32, payload []byte, baseDataFrames uint64, firstPad *padding.Range) error {
	numFrames := (len(payload) + MaxFramePayload - 1) / MaxFramePayload
	if s.sendSeq+uint64(numFrames) > maxRecordsPerKey {
		s.closeWithError(errRecordLimit)
		return errRecordLimit
	}
	overhead := s.send.Overhead()
	maxRecordSize := tlsrecord.HeaderSize + FrameHeaderSize + MaxFramePayload + overhead
	if cap(s.writeBuf) < numFrames*maxRecordSize {
		s.writeBuf = make([]byte, maxWriteBatchFrames*maxRecordSize)
	}

	off := 0
	for i := 0; len(payload) > 0; i++ {
		chunkLen := min(len(payload), MaxFramePayload)
		chunk := payload[:chunkLen]
		payload = payload[chunkLen:]

		var padLength int
		if i == 0 && firstPad != nil {
			padLength, _ = padding.RandomInt(firstPad.Minimum, firstPad.Maximum)
		} else {
			padLength = s.paddingLength(FrameData, chunkLen, baseDataFrames+uint64(i))
		}
		padLength = max(0, min(padLength, MaxFramePayload-chunkLen))
		plainSize := FrameHeaderSize + chunkLen + padLength
		recordSize := tlsrecord.HeaderSize + plainSize + overhead

		record := s.writeBuf[off : off+recordSize]
		header := record[:tlsrecord.HeaderSize]
		header[0], header[1], header[2] = tlsrecord.TypeAppData, 0x03, 0x03
		binary.BigEndian.PutUint16(header[3:], uint16(plainSize+overhead))
		plain := record[tlsrecord.HeaderSize : tlsrecord.HeaderSize+plainSize]
		plain[0] = FrameData
		binary.BigEndian.PutUint32(plain[1:5], id)
		binary.BigEndian.PutUint16(plain[5:FrameHeaderSize], uint16(chunkLen))
		copy(plain[FrameHeaderSize:], chunk)
		if padLength > 0 {
			clear(plain[FrameHeaderSize+chunkLen:])
		}
		s.send.Seal(plain[:0], seqNonce(&s.sendNonce, s.sendSeq), plain, header)
		s.sendSeq++
		off += recordSize
	}
	if err := writeAll(s.conn, s.writeBuf[:off]); err != nil {
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
	header := s.readHeader[:]
	for {
		if _, err := io.ReadFull(s.reader, header); err != nil {
			return 0, 0, nil, err
		}
		if s.recvSeq >= maxRecordsPerKey {
			return 0, 0, nil, errRecordLimit
		}
		if !tlsrecord.ValidHeader(header) {
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
		plain, err := s.recv.Open(body[:0], seqNonce(&s.recvNonce, s.recvSeq), body, header)
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

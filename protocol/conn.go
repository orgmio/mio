package protocol

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/orgmio/mio/internal/tlsrecord"
	"github.com/orgmio/mio/protocol/padding"
)

// flushDelay 是写缓冲里留着不完整 TLS 记录时，最多等多久就强制发出。
const flushDelay = 50 * time.Millisecond

// Conn 是 mio 的加密传输：每个帧封装为一条 TLS Application Data 记录，
// 用 AES-256-GCM 加密，5 字节记录头作为附加数据参与认证，nonce 为记录序号。
//
// 并发：可以一个协程读、一个协程写同时进行；不能多个协程同时 Read。
type Conn struct {
	net.Conn
	reader *bufio.Reader

	send, recv       cipher.AEAD
	sendSeq, recvSeq uint64
	readBuf          []byte
	pending          []byte
	eof              bool

	writeMu        sync.Mutex
	sendDataFrames uint64
	writePending   []byte
	writeErr       error
	flushTimer     *time.Timer
	policy         PaddingPolicy
	nextPadding    *padding.Range
}

// NewConn 用已派生好的密钥在 conn 上建立 mio 加密传输；reader 为 nil 时从 conn 直接读。
// 通常由 Handshake（客户端）或 Accept（服务端）创建，自行完成握手时也可以直接使用。
func NewConn(conn net.Conn, reader *bufio.Reader, send, recv cipher.AEAD) *Conn {
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	return &Conn{Conn: conn, reader: reader, send: send, recv: recv, policy: DefaultPadding{}}
}

func (c *Conn) rekey(send, recv cipher.AEAD) {
	c.send, c.recv = send, recv
	c.sendSeq, c.recvSeq = 0, 0
}

// SetPaddingPolicy 替换填充策略；p 为 nil 时恢复 DefaultPadding。
func (c *Conn) SetPaddingPolicy(p PaddingPolicy) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if p == nil {
		p = DefaultPadding{}
	}
	c.policy = p
}

// SetNextPadding 让下一个 data 帧的填充长度在 [minimum, maximum] 内随机，只生效一次，优先于填充策略。
func (c *Conn) SetNextPadding(minimum, maximum int) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.nextPadding = &padding.Range{Minimum: minimum, Maximum: maximum}
}

// CloseWrite 发出缓冲的数据和 close 帧，通知对端不再发送数据，之后仍可继续读取。
func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.stopFlushTimer()
	if c.writeErr != nil {
		return c.writeErr
	}
	if err := c.flushWriteBuffer(true); err != nil {
		return err
	}
	return c.writeFrame(FrameClose, nil)
}

func (c *Conn) Close() error {
	c.writeMu.Lock()
	c.stopFlushTimer()
	c.writeMu.Unlock()
	return c.Conn.Close()
}

func (c *Conn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.eof {
			return 0, io.EOF
		}
		typ, payload, err := c.readFrame(false)
		if err != nil {
			return 0, err
		}
		switch typ {
		case FrameData:
			c.pending = payload
		case FrameClose:
			c.eof = true
		default:
			// 不认识的帧类型直接跳过，留给以后扩展。
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.writePending = append(c.writePending, p...)
	if err := c.flushWriteBuffer(false); err != nil {
		c.writeErr = err
		return len(p), err
	}
	if len(c.writePending) > 0 {
		c.scheduleFlush()
	}
	return len(p), nil
}

// scheduleFlush 在缓冲里留着不完整的 TLS 记录时，过 flushDelay 强制发出，避免对端一直等不到数据。
func (c *Conn) scheduleFlush() {
	if c.flushTimer == nil {
		c.flushTimer = time.AfterFunc(flushDelay, c.forceFlush)
		return
	}
	c.flushTimer.Reset(flushDelay)
}

func (c *Conn) stopFlushTimer() {
	if c.flushTimer != nil {
		c.flushTimer.Stop()
	}
}

func (c *Conn) forceFlush() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil || len(c.writePending) == 0 {
		return
	}
	if err := c.flushWriteBuffer(true); err != nil {
		c.writeErr = err
	}
}

func (c *Conn) writeFrame(typ byte, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return errors.New("frame payload too large")
	}
	limit := tlsrecord.MaxBody - c.send.Overhead() - FrameHeaderSize - len(payload)
	var padLength int
	var err error
	if typ == FrameData && c.nextPadding != nil {
		lo := max(0, min(c.nextPadding.Minimum, limit))
		hi := max(lo, min(c.nextPadding.Maximum, limit))
		padLength, err = padding.RandomInt(lo, hi)
		c.nextPadding = nil
	} else {
		padLength, err = c.policy.PaddingLength(typ, len(payload), c.sendDataFrames, limit)
	}
	if err != nil {
		return err
	}
	padLength = max(0, min(padLength, limit))
	pad, err := padding.RandomBytes(padLength)
	if err != nil {
		return err
	}

	plain := make([]byte, FrameHeaderSize+len(payload)+len(pad))
	plain[0] = typ
	binary.BigEndian.PutUint16(plain[1:FrameHeaderSize], uint16(len(payload)))
	copy(plain[FrameHeaderSize:], payload)
	copy(plain[FrameHeaderSize+len(payload):], pad)

	var header [tlsrecord.HeaderSize]byte
	header[0], header[1], header[2] = tlsrecord.TypeAppData, 0x03, 0x03
	binary.BigEndian.PutUint16(header[3:], uint16(len(plain)+c.send.Overhead()))
	record := make([]byte, 0, tlsrecord.HeaderSize+len(plain)+c.send.Overhead())
	record = append(record, header[:]...)
	record = c.send.Seal(record, nonce(c.send, c.sendSeq), plain, header[:])
	c.sendSeq++
	if typ == FrameData {
		c.sendDataFrames++
	}
	return writeAll(c.Conn, record)
}

// flushWriteBuffer 尽量让一个内层 TLS 记录对应一个帧；closing 为 true 时把剩余数据全部发出。
func (c *Conn) flushWriteBuffer(closing bool) error {
	for len(c.writePending) > 0 {
		if len(c.writePending) < tlsrecord.HeaderSize {
			if !closing && tlsrecord.IsPossiblePrefix(c.writePending) {
				return nil
			}
			return c.writeEncryptedPending(len(c.writePending))
		}

		recordLength, isTLSRecord := tlsrecord.Length(c.writePending)
		if isTLSRecord {
			if len(c.writePending) < recordLength {
				if !closing {
					return nil
				}
				return c.writeEncryptedPending(len(c.writePending))
			}
			if err := c.writeEncryptedPending(recordLength); err != nil {
				return err
			}
			continue
		}

		if err := c.writeEncryptedPending(min(len(c.writePending), MaxFramePayload)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) writeEncryptedPending(length int) error {
	for p := c.writePending[:length]; len(p) > 0; {
		n := min(len(p), MaxFramePayload)
		if err := c.writeFrame(FrameData, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	c.writePending = c.writePending[length:]
	if len(c.writePending) == 0 {
		c.writePending = nil
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
func (c *Conn) readFrame(skipForeign bool) (byte, []byte, error) {
	var header [tlsrecord.HeaderSize]byte
	for {
		if _, err := io.ReadFull(c.reader, header[:]); err != nil {
			return 0, nil, err
		}
		if !tlsrecord.ValidHeader(header[:]) {
			return 0, nil, errors.New("invalid record header")
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if cap(c.readBuf) < length {
			c.readBuf = make([]byte, tlsrecord.MaxBody)
		}
		body := c.readBuf[:length]
		if _, err := io.ReadFull(c.reader, body); err != nil {
			return 0, nil, err
		}

		plain, err := c.recv.Open(body[:0], nonce(c.recv, c.recvSeq), body, header[:])
		if err != nil {
			if skipForeign {
				continue
			}
			return 0, nil, errors.New("decrypt record failed")
		}
		c.recvSeq++
		if len(plain) < FrameHeaderSize {
			return 0, nil, errors.New("short frame")
		}
		payloadLength := int(binary.BigEndian.Uint16(plain[1:FrameHeaderSize]))
		if payloadLength > len(plain)-FrameHeaderSize {
			return 0, nil, errors.New("invalid frame payload length")
		}
		return plain[0], plain[FrameHeaderSize : FrameHeaderSize+payloadLength], nil
	}
}

// waitReady 等待服务端的就绪帧并返回其服务端密钥份额，之前收到的真站记录会被丢弃。
func (c *Conn) waitReady() ([]byte, error) {
	typ, payload, err := c.readFrame(true)
	if err != nil {
		return nil, err
	}
	if typ != FrameReady {
		return nil, errors.New("unexpected frame before ready")
	}
	return append([]byte(nil), payload...), nil
}

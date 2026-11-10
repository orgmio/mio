package protocol

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/orgmio/mio/protocol/padding"
)

const (
	frameReady byte = 0
	frameData  byte = 1
	frameClose byte = 2
	frameTLS   byte = 3
	framePad   byte = 4

	maxFramePayload = 16384 - 1
	frameHeaderSize = 3
)

// transportAEADs 由共享密钥、密码与双方 random 派生两个方向各自独立的密钥；secret 为 nil 时只用密码（握手期）。
func transportAEADs(password string, secret, clientRandom, serverRandom []byte, isClient bool) (send, recv cipher.AEAD, err error) {
	salt := append(append([]byte{}, clientRandom...), serverRandom...)
	ikm := append(append([]byte{}, secret...), password...)
	c2s, err := newGCM(ikm, salt, "mio c2s")
	if err != nil {
		return nil, nil, err
	}
	s2c, err := newGCM(ikm, salt, "mio s2c")
	if err != nil {
		return nil, nil, err
	}
	if isClient {
		return c2s, s2c, nil
	}
	return s2c, c2s, nil
}

func newGCM(ikm, salt []byte, label string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, ikm, salt, label, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Encrypt 将普通数据封装为带长度和填充的 TLS Application Data 记录；确认目标 TLS 握手后，完整 TLS record 原样透传。
type Encrypt struct {
	net.Conn
	reader           *bufio.Reader
	send             cipher.AEAD
	recv             cipher.AEAD
	sendSeq          uint64
	recvSeq          uint64
	sendDataFrames   uint64
	pending          []byte
	writePending     []byte
	tlsSend          bool
	tlsRecv          bool
	tlsSendDetected  bool
	tlsRecvDetected  bool
	rawTLSIncomplete bool
	nextPadding      *padding.Range
	eof              bool
	writeMu          sync.Mutex
}

func newEncrypt(conn net.Conn, reader *bufio.Reader, send, recv cipher.AEAD) *Encrypt {
	return &Encrypt{Conn: conn, reader: reader, send: send, recv: recv}
}

func nonce(aead cipher.AEAD, seq uint64) []byte {
	n := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(n[len(n)-8:], seq)
	return n
}

// Accept 为已认证的连接建立服务端加密传输：用密码密钥发出带服务端密钥份额的就绪帧，再切换到混合密钥交换派生的密钥。
func Accept(conn net.Conn, reader *bufio.Reader, password string, clientRandom, serverRandom, share []byte) (net.Conn, error) {
	reply, secret, err := serverExchange(share)
	if err != nil {
		return nil, err
	}
	send, recv, err := transportAEADs(password, nil, clientRandom, serverRandom, false)
	if err != nil {
		return nil, err
	}
	enc := newEncrypt(conn, reader, send, recv)
	if err := enc.writeFrame(frameReady, reply); err != nil {
		return nil, err
	}
	send, recv, err = transportAEADs(password, secret, clientRandom, serverRandom, false)
	if err != nil {
		return nil, err
	}
	enc.rekey(send, recv)
	return enc, nil
}

func (c *Encrypt) rekey(send, recv cipher.AEAD) {
	c.send, c.recv = send, recv
	c.sendSeq, c.recvSeq = 0, 0
}

func (c *Encrypt) SetNextPadding(minimum, maximum int) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.nextPadding = &padding.Range{Minimum: minimum, Maximum: maximum}
}

// CloseWrite 通知对端不再发送数据，仍可继续读取。
func (c *Encrypt) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.flushWriteBuffer(true); err != nil {
		return err
	}
	if c.rawTLSIncomplete {
		if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
			return cw.CloseWrite()
		}
		return c.Conn.Close()
	}
	return c.writeFrame(frameClose, nil)
}

func (c *Encrypt) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.eof {
			return 0, io.EOF
		}
		typ, payload, err := c.readFrame(false)
		if err != nil {
			return 0, err
		}
		switch typ {
		case frameData:
			c.pending = payload
			if len(payload) >= RecordHeaderSize+1 && padding.HasHandshakeStart(payload[:RecordHeaderSize], payload[RecordHeaderSize:]) {
				c.tlsRecvDetected = true
			}
		case frameTLS:
			c.pending = payload
		case framePad:
			continue
		case frameClose:
			c.eof = true
		default:
			return 0, errors.New("unknown frame type")
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Encrypt) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	c.writePending = append(c.writePending, p...)
	if err := c.flushWriteBuffer(false); err != nil {
		return len(p), err
	}
	return len(p), nil
}

func (c *Encrypt) writeFrame(typ byte, payload []byte) error {
	return c.writeFrameWithPadding(typ, payload, false)
}

func (c *Encrypt) writeFrameWithPadding(typ byte, payload []byte, padLikeData bool) error {
	if len(payload) > 0xffff {
		return errors.New("frame payload too large")
	}
	maxPadding := maxRecordBody - c.send.Overhead() - frameHeaderSize - len(payload)
	var pad []byte
	var err error
	if typ == frameData && c.nextPadding != nil {
		pad, err = padding.RandomPadding(c.nextPadding.Minimum, c.nextPadding.Maximum, maxPadding)
		c.nextPadding = nil
	} else {
		pad, err = padding.FramePadding(len(payload), c.sendDataFrames, typ == frameReady, typ == frameData || padLikeData, maxPadding)
	}
	if err != nil {
		return err
	}
	plain := make([]byte, frameHeaderSize+len(payload)+len(pad))
	plain[0] = typ
	binary.BigEndian.PutUint16(plain[1:3], uint16(len(payload)))
	copy(plain[frameHeaderSize:], payload)
	copy(plain[frameHeaderSize+len(payload):], pad)

	bodyLen := len(plain) + c.send.Overhead()
	record := make([]byte, RecordHeaderSize, RecordHeaderSize+bodyLen)
	record[0], record[1], record[2] = RecordAppData, 0x03, 0x03
	binary.BigEndian.PutUint16(record[3:], uint16(bodyLen))
	record = c.send.Seal(record, nonce(c.send, c.sendSeq), plain, nil)
	c.sendSeq++
	if typ == frameData {
		c.sendDataFrames++
	}

	return writeAll(c.Conn, record)
}

func (c *Encrypt) flushWriteBuffer(final bool) error {
	for len(c.writePending) > 0 {
		if len(c.writePending) < RecordHeaderSize {
			if !final && padding.IsPossibleRecordPrefix(c.writePending) {
				return nil
			}
			if final && c.tlsSend {
				if err := writeAll(c.Conn, c.writePending); err != nil {
					return err
				}
				c.rawTLSIncomplete = true
				c.writePending = nil
				return nil
			}
			return c.writeEncryptedPending(len(c.writePending))
		}

		recordLength, isTLSRecord := padding.RecordLength(c.writePending)
		if isTLSRecord {
			if len(c.writePending) < recordLength {
				if !final {
					return nil
				}
				if c.tlsSend {
					if err := writeAll(c.Conn, c.writePending); err != nil {
						return err
					}
					c.rawTLSIncomplete = true
					c.writePending = nil
					return nil
				}
				return c.writeEncryptedPending(len(c.writePending))
			}
			record := c.writePending[:recordLength]
			if c.tlsSend || (c.tlsSendDetected && record[0] == RecordAppData) {
				c.tlsSend = true
				if err := c.writeTLSRecord(record); err != nil {
					return err
				}
			} else {
				if err := c.writeEncrypted(record); err != nil {
					return err
				}
				if padding.IsHandshakeStart(record) {
					c.tlsSendDetected = true
				}
			}
			c.consumeWritePending(recordLength)
			continue
		}

		return c.writeEncryptedPending(min(len(c.writePending), maxFramePayload))
	}
	return nil
}

func (c *Encrypt) writeTLSRecord(record []byte) error {
	if c.sendDataFrames < 8 {
		if err := c.writeFrameWithPadding(framePad, nil, true); err != nil {
			return err
		}
	}
	if err := writeAll(c.Conn, record); err != nil {
		return err
	}
	c.sendDataFrames++
	return nil
}

func (c *Encrypt) writeEncryptedPending(length int) error {
	if err := c.writeEncrypted(c.writePending[:length]); err != nil {
		return err
	}
	c.consumeWritePending(length)
	return nil
}

func (c *Encrypt) writeEncrypted(p []byte) error {
	for len(p) > 0 {
		n := min(len(p), maxFramePayload)
		if err := c.writeFrame(frameData, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func (c *Encrypt) consumeWritePending(length int) {
	c.writePending = c.writePending[length:]
	if len(c.writePending) == 0 {
		c.writePending = nil
	}
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

// readFrame 读取并解密一条记录；认证后仅在已确认 TLS 握手的方向接受未套 AEAD 的 TLS ApplicationData record。
func (c *Encrypt) readFrame(skipForeign bool) (byte, []byte, error) {
	for {
		header := make([]byte, RecordHeaderSize)
		if _, err := io.ReadFull(c.reader, header); err != nil {
			return 0, nil, err
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if !ValidRecordHeader(header, length) {
			return 0, nil, errors.New("invalid record header")
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(c.reader, body); err != nil {
			return 0, nil, err
		}

		plain, err := c.recv.Open(nil, nonce(c.recv, c.recvSeq), body, nil)
		if err != nil {
			if skipForeign {
				continue
			}
			record := append(header, body...)
			if c.tlsRecv || (c.tlsRecvDetected && header[0] == RecordAppData) {
				c.tlsRecv = true
				return frameTLS, record, nil
			}
			return 0, nil, errors.New("decrypt record failed")
		}
		c.recvSeq++
		if len(plain) < frameHeaderSize {
			return 0, nil, errors.New("short frame")
		}
		payloadLength := int(binary.BigEndian.Uint16(plain[1:3]))
		if payloadLength > len(plain)-frameHeaderSize {
			return 0, nil, errors.New("invalid frame payload length")
		}
		return plain[0], plain[frameHeaderSize : frameHeaderSize+payloadLength], nil
	}
}

// waitReady 等待服务端的就绪帧并返回其服务端密钥份额，之前收到的真站记录会被丢弃。
func (c *Encrypt) waitReady() ([]byte, error) {
	typ, payload, err := c.readFrame(true)
	if err != nil {
		return nil, err
	}
	if typ != frameReady {
		return nil, errors.New("unexpected frame before ready")
	}
	return payload, nil
}

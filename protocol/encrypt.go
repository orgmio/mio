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
)

const (
	frameReady byte = 0
	frameData  byte = 1
	frameClose byte = 2

	maxFramePayload = 16384 - 1
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

// Encrypt 把数据封装成伪装成 TLS Application Data 的记录，明文为 [帧类型][负载]，nonce 为每方向的递增计数。
type Encrypt struct {
	net.Conn
	reader  *bufio.Reader
	send    cipher.AEAD
	recv    cipher.AEAD
	sendSeq uint64
	recvSeq uint64
	pending []byte
	eof     bool
	writeMu sync.Mutex
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

// CloseWrite 通知对端不再发送数据，仍可继续读取。
func (c *Encrypt) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
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
		case frameClose:
			c.eof = true
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Encrypt) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		n := min(len(p), maxFramePayload)
		if err := c.writeFrame(frameData, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *Encrypt) writeFrame(typ byte, payload []byte) error {
	plain := make([]byte, 1+len(payload))
	plain[0] = typ
	copy(plain[1:], payload)

	bodyLen := len(plain) + c.send.Overhead()
	record := make([]byte, RecordHeaderSize, RecordHeaderSize+bodyLen)
	record[0], record[1], record[2] = RecordAppData, 0x03, 0x03
	binary.BigEndian.PutUint16(record[3:], uint16(bodyLen))
	record = c.send.Seal(record, nonce(c.send, c.sendSeq), plain, nil)
	c.sendSeq++

	_, err := c.Conn.Write(record)
	return err
}

// readFrame 读取并解密一条记录；skipForeign 为 true 时丢弃无法解密的记录（真站残留的 TLS 记录）。
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
			return 0, nil, errors.New("decrypt record failed")
		}
		c.recvSeq++
		if len(plain) == 0 {
			return 0, nil, errors.New("empty frame")
		}
		return plain[0], plain[1:], nil
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

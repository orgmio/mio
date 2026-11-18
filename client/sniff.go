package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"crypto/tls"

	"github.com/orgmio/mio/protocol"
)

// Sniff 从连接写出的第一段数据里取出 TLS 的 SNI，与请求的域名不同时记一条日志。
type Sniff struct {
	net.Conn
	once sync.Once
	host string
}

func (c *Sniff) Write(p []byte) (int, error) {
	// 只看第一段数据，之后的写入不再解析。解析要跑一遍 TLS 握手，只在会输出 Debug 日志时做。
	c.once.Do(func() {
		if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			return
		}
		if sni := parseSNI(p); sni != "" && sni != c.host {
			slog.Debug("inbound/socks: sniffed protocol: tls, domain: " + sni)
		}
	})
	return c.Conn.Write(p)
}

// ReadFrom 让 io.Copy 按 mio 一个帧的大小读取，理由见 protocol 包里流的 ReadFrom。
func (c *Sniff) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, protocol.MaxFramePayload)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			written, writeErr := c.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func (c *Sniff) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

var errSNIDone = errors.New("sni parsed")

func parseSNI(data []byte) string {
	if len(data) < 6 || data[0] != 0x16 {
		return ""
	}
	var sni string
	conn := tls.Server(replayConn{Reader: bytes.NewReader(data)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, errSNIDone
		},
	})
	_ = conn.Handshake()
	return sni
}

type replayConn struct{ *bytes.Reader }

func (replayConn) Write(p []byte) (int, error)      { return len(p), nil }
func (replayConn) Close() error                     { return nil }
func (replayConn) LocalAddr() net.Addr              { return nil }
func (replayConn) RemoteAddr() net.Addr             { return nil }
func (replayConn) SetDeadline(time.Time) error      { return nil }
func (replayConn) SetReadDeadline(time.Time) error  { return nil }
func (replayConn) SetWriteDeadline(time.Time) error { return nil }

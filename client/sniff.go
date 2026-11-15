package client

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"crypto/tls"
)

// Sniff 从连接写出的第一段数据里取出 TLS 的 SNI，与请求的域名不同时记一条日志。
type Sniff struct {
	net.Conn
	once sync.Once
	host string
}

func (c *Sniff) logOnce(sni string) {
	c.once.Do(func() {
		if sni != "" && sni != c.host {
			slog.Debug("inbound/socks: sniffed protocol: tls, domain: " + sni)
		}
	})
}

func (c *Sniff) Write(p []byte) (int, error) {
	c.logOnce(parseSNI(p))
	return c.Conn.Write(p)
}

func (c *Sniff) Close() error {
	c.logOnce("")
	return c.Conn.Close()
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

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

// sniConn 在客户端发出的第一段数据里提取 TLS SNI 并输出连接日志。
type sniConn struct {
	net.Conn
	once sync.Once
	from string
	dest string
	host string // SOCKS5 请求里的域名，没有 SNI 时作为回退
}

func (c *sniConn) logOnce(sni string) {
	c.once.Do(func() {
		if sni == "" {
			sni = c.host
		}
		if sni != "" {
			slog.Info("new connection", "from", c.from, "dest", c.dest, "sni", sni)
		} else {
			slog.Info("new connection", "from", c.from, "dest", c.dest)
		}
	})
}

func (c *sniConn) Write(p []byte) (int, error) {
	c.logOnce(parseSNI(p))
	return c.Conn.Write(p)
}

func (c *sniConn) Close() error {
	c.logOnce("")
	return c.Conn.Close()
}

// CloseWrite 保留 TCP 半关闭，避免被嵌入的接口吞掉。
func (c *sniConn) CloseWrite() error {
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

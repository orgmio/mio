package protocol

import (
	"io"
	"net"
	"time"
)

// Stream 是 QUIC stream 需要满足的最小接口，quic-go 与 uquic 的类型都符合。
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// StreamConn 把 QUIC stream 适配成 net.Conn，CloseWrite 只关闭发送方向。
type StreamConn struct {
	Stream
	cancelRead func()
	local      net.Addr
	remote     net.Addr
}

func NewStreamConn(s Stream, cancelRead func(), local, remote net.Addr) *StreamConn {
	return &StreamConn{Stream: s, cancelRead: cancelRead, local: local, remote: remote}
}

func (c *StreamConn) LocalAddr() net.Addr  { return c.local }
func (c *StreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *StreamConn) CloseWrite() error { return c.Stream.Close() }

func (c *StreamConn) Close() error {
	c.cancelRead()
	return c.Stream.Close()
}

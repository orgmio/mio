package client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol"
)

// ListenUDP 建立 UDP 关联，供调用方在本地选择 IP 端点。
// WriteTo 接收的地址和 ReadFrom 返回的地址均为 UDP 端点，由 IP 地址和端口组成。
func (d *Dialer) ListenUDP(ctx context.Context) (net.PacketConn, error) {
	stream, err := d.dial(ctx, protocol.StreamRequest{UDPAssociate: true})
	if err != nil {
		return nil, err
	}
	return &udpPacketConn{stream: stream}, nil
}

type udpPacketConn struct {
	stream  net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	buf     [protocol.MaxDatagramSize]byte
}

func (c *udpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		stream := udpStreamIO{Conn: c.stream}
		datagram, err := protocol.ReadDatagram(&stream, c.buf[:])
		if err != nil {
			stream.closeOnError(err)
			return 0, nil, err
		}
		source, payload, err := protocol.ParseDatagram(datagram)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddrPort(source)
		if err == nil {
			return copy(p, payload), net.UDPAddrFromAddrPort(addr), nil
		}
	}
}

// 数据报之间发生超时后可以继续收发。数据报传输到一半被中断可能使流失去同步，
// 因此会关闭 UDP 关联。
type udpStreamIO struct {
	net.Conn
	progress bool
}

func (s *udpStreamIO) Read(p []byte) (int, error) {
	n, err := s.Conn.Read(p)
	s.progress = s.progress || n > 0
	return n, err
}

func (s *udpStreamIO) Write(p []byte) (int, error) {
	n, err := s.Conn.Write(p)
	s.progress = s.progress || n > 0
	return n, err
}

func (s *udpStreamIO) closeOnError(err error) {
	var timeout net.Error
	if s.progress || !errors.As(err, &timeout) || !timeout.Timeout() {
		s.Conn.Close()
	}
}

func (c *udpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("mio UDP requires an IP endpoint")
	}
	target, err := netip.ParseAddrPort(addr.String())
	if err != nil || target.Addr().Zone() != "" || target.Port() == 0 {
		return 0, errors.New("invalid mio UDP destination")
	}
	var datagram bytes.Buffer
	if err := protocol.WriteRequest(&datagram, target.String()); err != nil {
		return 0, err
	}
	if len(p) > protocol.MaxDatagramSize-datagram.Len() {
		return 0, errors.New("mio UDP datagram too large")
	}
	datagram.Write(p)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	stream := udpStreamIO{Conn: c.stream}
	if err := protocol.WriteDatagram(&stream, datagram.Bytes()); err != nil {
		stream.closeOnError(err)
		return 0, err
	}
	return len(p), nil
}

func (c *udpPacketConn) Close() error                       { return c.stream.Close() }
func (c *udpPacketConn) LocalAddr() net.Addr                { return c.stream.LocalAddr() }
func (c *udpPacketConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *udpPacketConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *udpPacketConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

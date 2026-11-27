package client

import (
	"context"
	"encoding/binary"
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
	stream   net.Conn
	readMu   sync.Mutex
	writeMu  sync.Mutex
	buf      [protocol.MaxDatagramSize]byte
	writeBuf [protocol.MaxDatagramSize]byte
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
	ap := target.Addr().Unmap()
	var hdr [19]byte // 最大 IPv6: atyp(1) + addr(16) + port(2)
	var hdrLen int
	if ap.Is4() {
		hdr[0] = 1
		a4 := ap.As4()
		copy(hdr[1:5], a4[:])
		binary.BigEndian.PutUint16(hdr[5:7], target.Port())
		hdrLen = 7
	} else {
		hdr[0] = 4
		a16 := ap.As16()
		copy(hdr[1:17], a16[:])
		binary.BigEndian.PutUint16(hdr[17:19], target.Port())
		hdrLen = 19
	}
	if len(p) > protocol.MaxDatagramSize-hdrLen {
		return 0, errors.New("mio UDP datagram too large")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	copy(c.writeBuf[:hdrLen], hdr[:hdrLen])
	copy(c.writeBuf[hdrLen:], p)
	stream := udpStreamIO{Conn: c.stream}
	if err := protocol.WriteDatagram(&stream, c.writeBuf[:hdrLen+len(p)]); err != nil {
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

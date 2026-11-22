package server

import (
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/quic-go"
	"golang.org/x/net/ipv4"
)

const virtualQueueLen = 1024

// virtualConn 是交给 quic-go 的 socket：只读得到已被分流给 mio 的数据报，写出直接走真实的 UDP socket。
//
// 它实现了 quic-go 的 OOBCapablePacketConn 和 ReadBatch，quic-go 因此把它当作真正的 UDP socket：
// 发送用 sendmsg 带上 GSO、ECN 和 packet info，socket 选项（DF、缓冲大小、接收 ECN 与 packet info）直接设在真实 socket 上；
// 接收时一次取走队列里所有已到的数据报，内核给的控制消息原样交过去。
type virtualConn struct {
	sock *net.UDPConn
	in   chan *udpPacket
	done chan struct{}
	once sync.Once

	mu       sync.Mutex
	deadline time.Time
	wake     chan struct{}
}

// 少了任何一个方法，quic-go 都会悄悄退回到逐包收发、没有 GSO 的慢路径，所以在编译期确认。
var _ quic.OOBCapablePacketConn = (*virtualConn)(nil)

func newVirtualConn(sock *net.UDPConn) *virtualConn {
	return &virtualConn{
		sock: sock,
		in:   make(chan *udpPacket, virtualQueueLen),
		done: make(chan struct{}),
		wake: make(chan struct{}),
	}
}

// push 把数据报放进 QUIC 的接收队列，队列满时丢弃并返回 false（p 仍归调用方）。
func (v *virtualConn) push(p *udpPacket) bool {
	select {
	case v.in <- p:
		return true
	default:
		return false
	}
}

// next 等待下一个数据报，遵守读超时。
func (v *virtualConn) next() (*udpPacket, error) {
	for {
		v.mu.Lock()
		deadline, wake := v.deadline, v.wake
		v.mu.Unlock()

		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			expired = timer.C
		}

		select {
		case p := <-v.in:
			if timer != nil {
				timer.Stop()
			}
			return p, nil
		case <-v.done:
			if timer != nil {
				timer.Stop()
			}
			return nil, net.ErrClosed
		case <-expired:
			return nil, os.ErrDeadlineExceeded
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

// ReadBatch 是 quic-go 的收包入口：等到第一个数据报，再把队列里已有的一并取走。
func (v *virtualConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	p, err := v.next()
	if err != nil {
		return 0, err
	}
	n := 0
	for {
		m := &ms[n]
		m.N = copy(m.Buffers[0], p.data[:p.n])
		m.NN = copy(m.OOB, p.oob[:p.oobn])
		m.Flags = 0
		m.Addr = p.addr
		putPacket(p)
		n++
		if n == len(ms) {
			return n, nil
		}
		select {
		case p = <-v.in:
		default:
			return n, nil
		}
	}
}

func (v *virtualConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p, err := v.next()
	if err != nil {
		return 0, nil, err
	}
	n, addr := copy(b, p.data[:p.n]), p.addr
	putPacket(p)
	return n, addr, nil
}

func (v *virtualConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	p, err := v.next()
	if err != nil {
		return 0, 0, 0, nil, err
	}
	n, oobn, addr = copy(b, p.data[:p.n]), copy(oob, p.oob[:p.oobn]), p.addr
	putPacket(p)
	return n, oobn, 0, addr, nil
}

func (v *virtualConn) WriteTo(b []byte, addr net.Addr) (int, error) { return v.sock.WriteTo(b, addr) }
func (v *virtualConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	return v.sock.WriteMsgUDP(b, oob, addr)
}
func (v *virtualConn) SyscallConn() (syscall.RawConn, error) { return v.sock.SyscallConn() }
func (v *virtualConn) SetReadBuffer(n int) error             { return v.sock.SetReadBuffer(n) }
func (v *virtualConn) SetWriteBuffer(n int) error            { return v.sock.SetWriteBuffer(n) }
func (v *virtualConn) LocalAddr() net.Addr                   { return v.sock.LocalAddr() }

func (v *virtualConn) Close() error {
	v.once.Do(func() { close(v.done) })
	return nil
}

func (v *virtualConn) SetDeadline(t time.Time) error { return v.SetReadDeadline(t) }

func (v *virtualConn) SetReadDeadline(t time.Time) error {
	v.mu.Lock()
	v.deadline = t
	close(v.wake)
	v.wake = make(chan struct{})
	v.mu.Unlock()
	return nil
}

func (v *virtualConn) SetWriteDeadline(time.Time) error { return nil }

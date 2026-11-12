package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol/quicauth"
)

const (
	maxPending      = 4
	pendingTimeout  = 5 * time.Second
	relayIdle       = 2 * time.Minute
	mioFlowIdle     = 10 * time.Minute
	virtualQueueLen = 1024
)

type flowKind int

const (
	flowPending flowKind = iota
	flowMio
	flowRelay
)

type flow struct {
	kind    flowKind
	pending [][]byte
	relay   *net.UDPConn
	last    time.Time
}

// demux 按客户端地址把 UDP 流分流：带有效标记的交给 QUIC 服务，其余原样转发给真站。
type demux struct {
	sock     *net.UDPConn
	password string
	dest     *net.UDPAddr
	replay   *quicauth.ReplayCache
	virtual  *virtualConn

	mu    sync.Mutex
	flows map[netip.AddrPort]*flow
}

func newDemux(sock *net.UDPConn, password string, dest *net.UDPAddr) *demux {
	return &demux{
		sock:     sock,
		password: password,
		dest:     dest,
		replay:   quicauth.NewReplayCache(),
		virtual:  newVirtualConn(sock),
		flows:    make(map[netip.AddrPort]*flow),
	}
}

func (d *demux) run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		d.sock.Close()
		d.virtual.Close()
	}()
	go d.cleanup(ctx)

	buf := make([]byte, 65535)
	for {
		n, addr, err := d.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("udp read failed", "err", err)
			}
			return
		}
		addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		d.handle(addr, append([]byte(nil), buf[:n]...))
	}
}

func (d *demux) handle(addr netip.AddrPort, pkt []byte) {
	d.mu.Lock()
	f := d.flows[addr]
	if f == nil {
		f = &flow{}
		d.flows[addr] = f
	}
	f.last = time.Now()

	switch f.kind {
	case flowMio:
		d.mu.Unlock()
		d.virtual.push(pkt, addr)
		return
	case flowRelay:
		relay := f.relay
		d.mu.Unlock()
		if relay != nil {
			relay.Write(pkt)
		}
		return
	}

	random, status := initialClientHelloRandom(pkt)
	switch {
	case status == initialRandom && d.replay.Check(d.password, random):
		f.kind = flowMio
		queued := append(f.pending, pkt)
		f.pending = nil
		d.mu.Unlock()
		slog.Debug("quic flow accepted", "from", addr.String())
		for _, p := range queued {
			d.virtual.push(p, addr)
		}
	case status == initialIncomplete && len(f.pending) < maxPending:
		f.pending = append(f.pending, pkt)
		d.mu.Unlock()
	default:
		queued := append(f.pending, pkt)
		f.pending = nil
		f.kind = flowRelay
		f.relay = d.openRelay(addr)
		relay := f.relay
		d.mu.Unlock()
		slog.Debug("quic flow relayed to dest", "from", addr.String())
		if relay != nil {
			for _, p := range queued {
				relay.Write(p)
			}
		}
	}
}

// openRelay 为这个客户端建立到真站的 UDP 连接，并把真站的回包转回客户端。
func (d *demux) openRelay(client netip.AddrPort) *net.UDPConn {
	if d.dest == nil {
		return nil
	}
	relay, err := net.DialUDP("udp", nil, d.dest)
	if err != nil {
		slog.Warn("dial dest udp failed", "err", err)
		return nil
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := relay.Read(buf)
			if err != nil {
				return
			}
			d.sock.WriteToUDPAddrPort(buf[:n], client)
		}
	}()
	return relay
}

func (d *demux) cleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now()
		d.mu.Lock()
		for addr, f := range d.flows {
			idle := now.Sub(f.last)
			expired := false
			switch f.kind {
			case flowPending:
				expired = idle > pendingTimeout
			case flowRelay:
				expired = idle > relayIdle
			case flowMio:
				expired = idle > mioFlowIdle
			}
			if !expired {
				continue
			}
			if f.relay != nil {
				f.relay.Close()
			}
			delete(d.flows, addr)
		}
		d.mu.Unlock()
	}
}

type packet struct {
	data []byte
	addr net.Addr
}

// virtualConn 是只提供已被分流给 mio 的数据包的 net.PacketConn，写出直接走真实的 UDP socket。
type virtualConn struct {
	sock *net.UDPConn
	in   chan packet
	done chan struct{}
	once sync.Once

	mu       sync.Mutex
	deadline time.Time
	wake     chan struct{}
}

func newVirtualConn(sock *net.UDPConn) *virtualConn {
	return &virtualConn{
		sock: sock,
		in:   make(chan packet, virtualQueueLen),
		done: make(chan struct{}),
		wake: make(chan struct{}),
	}
}

func (v *virtualConn) push(data []byte, addr netip.AddrPort) {
	select {
	case v.in <- packet{data: data, addr: net.UDPAddrFromAddrPort(addr)}:
	default:
	}
}

func (v *virtualConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		v.mu.Lock()
		deadline, wake := v.deadline, v.wake
		v.mu.Unlock()

		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			expired = timer.C
		}

		select {
		case pkt := <-v.in:
			if timer != nil {
				timer.Stop()
			}
			return copy(p, pkt.data), pkt.addr, nil
		case <-v.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-expired:
			return 0, nil, os.ErrDeadlineExceeded
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (v *virtualConn) WriteTo(p []byte, addr net.Addr) (int, error) { return v.sock.WriteTo(p, addr) }
func (v *virtualConn) LocalAddr() net.Addr                          { return v.sock.LocalAddr() }

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

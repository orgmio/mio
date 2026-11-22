package server

import (
	"context"
	"crypto/ecdh"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/orgmio/mio/protocol/quicauth"
)

const (
	maxPending     = 4
	pendingTimeout = 5 * time.Second
	relayIdle      = 2 * time.Minute
	mioFlowIdle    = 10 * time.Minute
	// maxUnknownFlows 是同时存在的未认证流（等待中的和转发给真站的）的上限，超出后新来源的包直接丢弃，
	// 以免有人换着源地址发包耗尽文件描述符和内存。
	maxUnknownFlows = 1024
	// packetSize 是一个数据报缓冲的大小。互联网上的 UDP 数据报不超过 1500 字节左右，quic-go 自己的收包缓冲也只有 1452 字节。
	packetSize = 2048
	// oobSize 是控制消息缓冲的大小，与 quic-go 相同，装得下 ECN 和 packet info。
	oobSize = 128
	// readBatch 是一次 recvmmsg 最多读取的数据报数。
	readBatch = 32
	// destRefresh 是重新解析真站 UDP 地址的间隔：真站常在 CDN 后面，IP 会变，TCP 每次连接都重新解析，UDP 也要跟上。
	destRefresh = 5 * time.Minute
)

// udpPacket 是从 socket 读到的一个数据报，连同内核给的控制消息（ECN、packet info），放在池里复用。
type udpPacket struct {
	data [packetSize]byte
	n    int
	oob  [oobSize]byte
	oobn int
	addr *net.UDPAddr // 内核给出的原始地址，原样交给 quic-go
}

var packetPool = sync.Pool{New: func() any { return new(udpPacket) }}

func getPacket() *udpPacket  { return packetPool.Get().(*udpPacket) }
func putPacket(p *udpPacket) { packetPool.Put(p) }

type flowKind int

const (
	flowPending flowKind = iota
	flowMio
	flowRelay
)

type flow struct {
	kind    flowKind
	pending []*udpPacket
	relay   *net.UDPConn
	last    time.Time
}

// demux 按客户端地址把 UDP 流分流：带有效标记的交给 QUIC 服务，其余原样转发给真站。
type demux struct {
	sock     *net.UDPConn
	destName string
	dest     atomic.Pointer[net.UDPAddr] // nil 表示还没解析成功，这时未标记的流量会被丢弃
	replay   *quicauth.ReplayCache
	virtual  *virtualConn

	mu      sync.Mutex
	flows   map[netip.AddrPort]*flow
	unknown int // flows 里不属于 mio 的流的数量
}

func newDemux(sock *net.UDPConn, server *ecdh.PublicKey, dest string) *demux {
	d := &demux{
		sock:     sock,
		destName: dest,
		replay:   quicauth.NewReplayCache(server),
		virtual:  newVirtualConn(sock),
		flows:    make(map[netip.AddrPort]*flow),
	}
	d.resolveDest()
	return d
}

// resolveDest 解析真站的 UDP 地址。失败时保留上一次的结果。
func (d *demux) resolveDest() {
	addr, err := net.ResolveUDPAddr("udp", d.destName)
	if err != nil {
		if d.dest.Load() == nil {
			slog.Warn("inbound/mio: resolve dest udp, unmarked quic traffic will be dropped", "err", err)
		}
		return
	}
	d.dest.Store(addr)
}

func (d *demux) refreshDest(ctx context.Context) {
	ticker := time.NewTicker(destRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.resolveDest()
		}
	}
}

// run 用 recvmmsg 成批读取数据报并分流。数据报缓冲来自池：交给 QUIC 或暂存起来的缓冲由接收方归还，这里换一个新的；
// 转发给真站的缓冲写完就能复用。
func (d *demux) run(ctx context.Context) {
	go func() {
		<-ctx.Done()
		d.sock.Close()
		d.virtual.Close()
	}()
	go d.cleanup(ctx)
	go d.refreshDest(ctx)

	conn := ipv4.NewPacketConn(d.sock)
	msgs := make([]ipv4.Message, readBatch)
	pkts := make([]*udpPacket, readBatch)
	for i := range msgs {
		pkts[i] = getPacket()
		msgs[i].Buffers = [][]byte{pkts[i].data[:]}
		msgs[i].OOB = pkts[i].oob[:]
	}
	for {
		n, err := conn.ReadBatch(msgs, 0)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("inbound/mio: udp read", "err", err)
			}
			return
		}
		now := time.Now()
		for i := range n {
			addr, ok := msgs[i].Addr.(*net.UDPAddr)
			if !ok {
				continue
			}
			p := pkts[i]
			p.n, p.oobn, p.addr = msgs[i].N, msgs[i].NN, addr
			ap := addr.AddrPort()
			if d.handle(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), p, now) {
				pkts[i] = getPacket()
				msgs[i].Buffers[0] = pkts[i].data[:]
				msgs[i].OOB = pkts[i].oob[:]
			}
		}
	}
}

// handle 分流一个数据报，返回 true 表示 p 已被交出（进了 QUIC 队列或暂存），调用方不能再用它。
func (d *demux) handle(addr netip.AddrPort, p *udpPacket, now time.Time) bool {
	d.mu.Lock()
	f := d.flows[addr]
	if f == nil {
		if d.unknown >= maxUnknownFlows {
			d.mu.Unlock()
			return false
		}
		f = &flow{}
		d.flows[addr] = f
		d.unknown++
	}
	f.last = now

	switch f.kind {
	case flowMio:
		d.mu.Unlock()
		return d.virtual.push(p)
	case flowRelay:
		relay := f.relay
		d.mu.Unlock()
		if relay != nil {
			relay.Write(p.data[:p.n])
		}
		return false
	}

	random, status := initialClientHelloRandom(p.data[:p.n])
	switch {
	case status == initialRandom && d.replay.Check(random):
		f.kind = flowMio
		d.unknown--
		queued := f.pending
		f.pending = nil
		d.mu.Unlock()
		slog.Debug("inbound/mio: quic flow from " + addr.String() + " accepted")
		for _, q := range queued {
			if !d.virtual.push(q) {
				putPacket(q)
			}
		}
		return d.virtual.push(p)
	case status == initialIncomplete && len(f.pending) < maxPending:
		f.pending = append(f.pending, p)
		d.mu.Unlock()
		return true
	default:
		queued := f.pending
		f.pending = nil
		f.kind = flowRelay
		f.relay = d.openRelay(addr)
		relay := f.relay
		d.mu.Unlock()
		slog.Debug("inbound/mio: quic flow from " + addr.String() + " relayed to dest")
		for _, q := range queued {
			if relay != nil {
				relay.Write(q.data[:q.n])
			}
			putPacket(q)
		}
		if relay != nil {
			relay.Write(p.data[:p.n])
		}
		return false
	}
}

// openRelay 为这个客户端建立到真站的 UDP 连接，并把真站的回包转回客户端。
func (d *demux) openRelay(client netip.AddrPort) *net.UDPConn {
	dest := d.dest.Load()
	if dest == nil {
		return nil
	}
	relay, err := net.DialUDP("udp", nil, dest)
	if err != nil {
		slog.Warn("inbound/mio: open udp connection to dest", "err", err)
		return nil
	}
	go func() {
		buf := make([]byte, packetSize)
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
		d.replay.Sweep(now)
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
			for _, q := range f.pending {
				putPacket(q)
			}
			if f.kind != flowMio {
				d.unknown--
			}
			delete(d.flows, addr)
		}
		d.mu.Unlock()
	}
}

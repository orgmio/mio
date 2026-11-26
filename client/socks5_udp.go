package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/orgmio/mio/protocol"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

const socksUDPHeaderSize = 3

func (node *SOCKS5Node) associateUDP(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	local, localOK := request.LocalAddr.(*net.TCPAddr)
	peer, peerOK := request.RemoteAddr.(*net.TCPAddr)
	if !localOK || !peerOK {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(node.dialer.ctx, cancel)
	defer stop()
	go func() {
		// 在 UDP 关联存续期间，TCP 控制连接保持空闲。
		var unexpected [1]byte
		request.Reader.Read(unexpected[:])
		cancel()
	}()

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	defer relay.Close()
	tunnel, err := node.dialer.dial(ctx, protocol.StreamRequest{UDPAssociate: true})
	if err != nil {
		return socks5.SendReply(writer, statute.RepServerFailure, nil)
	}
	defer tunnel.Close()
	unblock := context.AfterFunc(ctx, func() {
		relay.Close()
		tunnel.SetDeadline(time.Now())
	})
	defer unblock()

	if err := socks5.SendReply(writer, statute.RepSuccess, relay.LocalAddr()); err != nil {
		return err
	}
	var client atomic.Pointer[netip.AddrPort]
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		defer cancel()
		forwardSOCKSDatagrams(relay, tunnel, peer.AddrPort().Addr().Unmap(), request.RawDestAddr.Port, &client)
	}()

	reply := make([]byte, socksUDPHeaderSize+protocol.MaxDatagramSize)
	for {
		datagram, err := protocol.ReadDatagram(tunnel, reply[socksUDPHeaderSize:])
		if err != nil {
			cancel()
			<-sent
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if _, _, err := protocol.ParseDatagram(datagram); err != nil {
			continue
		}
		if addr := client.Load(); addr != nil {
			relay.WriteToUDPAddrPort(reply[:socksUDPHeaderSize+len(datagram)], *addr)
		}
	}
}

func forwardSOCKSDatagrams(relay *net.UDPConn, tunnel net.Conn, peer netip.Addr, port int, client *atomic.Pointer[netip.AddrPort]) {
	// 多预留 1 个字节，用于识别超长或被截断的数据报。
	packet := make([]byte, socksUDPHeaderSize+protocol.MaxDatagramSize+1)
	for {
		n, addr, err := relay.ReadFromUDPAddrPort(packet)
		if err != nil {
			return
		}
		if addr.Addr().Unmap() != peer || (port != 0 && int(addr.Port()) != port) {
			continue
		}
		if pinned := client.Load(); pinned != nil && *pinned != addr {
			continue
		}
		if n <= socksUDPHeaderSize || n == len(packet) || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			continue
		}
		datagram := packet[socksUDPHeaderSize:n]
		if _, _, err := protocol.ParseDatagram(datagram); err != nil {
			continue
		}
		if client.Load() == nil {
			client.Store(&addr)
		}
		if err := protocol.WriteDatagram(tunnel, datagram); err != nil {
			return
		}
	}
}

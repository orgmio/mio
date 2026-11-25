package server

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol"
)

const (
	maxUDPTargets = 64
	udpTargetIdle = time.Minute
	udpIOTimeout  = 5 * time.Second
)

func relayUDPAssociation(parent context.Context, tunnel net.Conn) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, func() { tunnel.SetDeadline(time.Now()) })

	targets := make(map[string]*net.UDPConn)
	var targetsMu, writeMu sync.Mutex
	var readers sync.WaitGroup
	defer func() {
		cancel()
		targetsMu.Lock()
		for _, socket := range targets {
			socket.Close()
		}
		targetsMu.Unlock()
		readers.Wait()
		stop()
	}()

	dialer := net.Dialer{Timeout: dialTimeout}
	buf := make([]byte, protocol.MaxDatagramSize)
	for ctx.Err() == nil {
		datagram, err := protocol.ReadDatagram(tunnel, buf)
		if err != nil {
			return
		}
		target, payload, err := protocol.ParseDatagram(datagram)
		if err != nil {
			continue
		}

		targetsMu.Lock()
		socket := targets[target]
		full := len(targets) >= maxUDPTargets
		targetsMu.Unlock()
		if socket == nil {
			if full {
				continue
			}
			conn, err := dialer.DialContext(ctx, "udp", target)
			if err != nil {
				continue
			}
			socket = conn.(*net.UDPConn)
			socket.SetReadDeadline(time.Now().Add(udpTargetIdle))
			targetsMu.Lock()
			targets[target] = socket
			targetsMu.Unlock()
			readers.Go(func() {
				defer func() {
					socket.Close()
					targetsMu.Lock()
					delete(targets, target)
					targetsMu.Unlock()
				}()
				relayUDPReplies(ctx, cancel, tunnel, &writeMu, socket)
			})
		}
		socket.SetWriteDeadline(time.Now().Add(udpIOTimeout))
		if _, err := socket.Write(payload); err == nil {
			socket.SetReadDeadline(time.Now().Add(udpTargetIdle))
		}
	}
}

func relayUDPReplies(ctx context.Context, cancel context.CancelFunc, tunnel net.Conn, writeMu *sync.Mutex, socket *net.UDPConn) {
	var source bytes.Buffer
	if err := protocol.WriteRequest(&source, socket.RemoteAddr().String()); err != nil {
		return
	}

	// One extra byte lets us discard truncated or oversized replies.
	reply := make([]byte, protocol.MaxDatagramSize+1)
	headerSize := copy(reply, source.Bytes())
	for {
		n, err := socket.Read(reply[headerSize:])
		if err != nil {
			return
		}
		socket.SetReadDeadline(time.Now().Add(udpTargetIdle))
		size := headerSize + n
		if size > protocol.MaxDatagramSize {
			continue
		}

		writeMu.Lock()
		if ctx.Err() != nil {
			writeMu.Unlock()
			return
		}
		tunnel.SetWriteDeadline(time.Now().Add(udpIOTimeout))
		err = protocol.WriteDatagram(tunnel, reply[:size])
		writeMu.Unlock()
		if err != nil {
			cancel()
			return
		}
	}
}

package protocal

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

func tcpMuxConfig() *yamux.Config {
	config := yamux.DefaultConfig()
	config.AcceptBacklog = 256
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 20 * time.Second
	config.ConnectionWriteTimeout = tunnelDialTimeout
	config.MaxStreamWindowSize = 16 * 1024 * 1024
	config.StreamOpenTimeout = tunnelDialTimeout
	config.StreamCloseTimeout = 5 * time.Second
	return config
}

func (c *TunnelClient) openTCPMuxStream(ctx context.Context, command byte, target string) (net.Conn, error) {
	for attempts := 0; attempts < 2; attempts++ {
		session, err := c.tcpMuxSession(ctx)
		if err != nil {
			return nil, err
		}
		stream, err := session.OpenStream()
		if err != nil {
			c.dropTCPMux(session)
			continue
		}
		if err := writeTunnelRequest(stream, c.key, command, target, time.Now()); err != nil {
			_ = stream.Close()
			c.dropTCPMux(session)
			continue
		}
		var status [1]byte
		if _, err := io.ReadFull(stream, status[:]); err != nil {
			_ = stream.Close()
			c.dropTCPMux(session)
			continue
		}
		if status[0] != 0 {
			_ = stream.Close()
			return nil, &tunnelRejectedError{code: status[0]}
		}
		if command == tunnelCommandTCP {
			return newVisionConn(stream), nil
		}
		return stream, nil
	}
	return nil, errors.New("TCP multiplex session unavailable")
}

func (c *TunnelClient) tcpMuxSession(ctx context.Context) (*yamux.Session, error) {
	c.tcpMuxMu.Lock()
	defer c.tcpMuxMu.Unlock()
	if c.tcpMux != nil && !c.tcpMux.IsClosed() {
		return c.tcpMux, nil
	}
	outer, err := c.openTCPTunnel(ctx, tunnelCommandMux, c.cover.address)
	if err != nil {
		return nil, err
	}
	session, err := yamux.Client(outer, tcpMuxConfig())
	if err != nil {
		_ = outer.Close()
		return nil, err
	}
	c.tcpMux = session
	return session, nil
}

func (c *TunnelClient) dropTCPMux(expected *yamux.Session) {
	c.tcpMuxMu.Lock()
	if c.tcpMux == expected {
		_ = c.tcpMux.Close()
		c.tcpMux = nil
	}
	c.tcpMuxMu.Unlock()
}

func (s *TunnelServer) serveTCPMux(ctx context.Context, conn net.Conn) error {
	session, err := yamux.Server(conn, tcpMuxConfig())
	if err != nil {
		return err
	}
	defer session.Close()
	go func() {
		<-ctx.Done()
		_ = session.Close()
	}()
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, yamux.ErrSessionShutdown) {
				return nil
			}
			return err
		}
		go func() {
			defer stream.Close()
			_ = s.handle(ctx, stream)
		}()
	}
}

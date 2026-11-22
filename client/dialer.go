package client

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol"
)

const (
	minProbeInterval = 10 * time.Minute
	maxProbeInterval = 30 * time.Minute
	probeTimeout     = 25 * time.Second
)

type transportChoice uint8

const (
	transportUnknown transportChoice = iota
	transportTCP
	transportQUIC
)

type dialResult struct {
	transport transportChoice
	tcp       *protocol.Session
	quic      *quicSession
	err       error
}

func (r dialResult) close() {
	if r.tcp != nil {
		r.tcp.Close()
	}
	if r.quic != nil {
		r.quic.Close()
	}
}

// Dialer 会并行探测 TCP 和 QUIC，随后在 10 到 30 分钟后重新比较两者。
type Dialer struct {
	peer protocol.Peer
	tcp  *tcpPool

	mu        sync.Mutex
	session   *quicSession
	selected  transportChoice
	probing   bool
	nextProbe time.Time
}

func NewDialer(peer protocol.Peer) *Dialer {
	return &Dialer{peer: peer, tcp: newTCPPool(peer)}
}

func (d *Dialer) Dial(ctx context.Context, target string) (net.Conn, error) {
	d.mu.Lock()
	if d.probing {
		session, selected := d.session, d.selected
		d.mu.Unlock()
		return d.dialSelected(ctx, target, selected, session)
	}
	if d.selected == transportUnknown || !time.Now().Before(d.nextProbe) {
		d.probing = true
		d.mu.Unlock()
		return d.probe(ctx, target)
	}
	session := d.session
	selected := d.selected
	d.mu.Unlock()

	return d.dialSelected(ctx, target, selected, session)
}

func (d *Dialer) dialSelected(ctx context.Context, target string, selected transportChoice, session *quicSession) (net.Conn, error) {
	if selected == transportQUIC && session != nil {
		conn, err := session.dialStream(ctx, target)
		if err == nil || errors.Is(err, protocol.ErrConnectFailed) || ctx.Err() != nil {
			return conn, err
		}
		if session.conn.Context().Err() != nil {
			d.drop(session)
		}
		slog.Debug("outbound/mio: h3 stream failed, falling back to tcp", "err", err)
	}

	conn, tcpErr := d.tcp.dial(ctx, target)
	if tcpErr == nil {
		if selected == transportQUIC {
			d.selectTransport(transportTCP, nil)
		}
		return conn, nil
	}
	if errors.Is(tcpErr, protocol.ErrConnectFailed) || ctx.Err() != nil {
		return conn, tcpErr
	}
	owned := false
	if session == nil || session.conn.Context().Err() != nil {
		var quicErr error
		session, quicErr = dialQUIC(ctx, d.peer)
		if quicErr != nil {
			return nil, errors.Join(tcpErr, quicErr)
		}
		owned = true
	}
	quicConn, quicErr := session.dialStream(ctx, target)
	if quicErr == nil {
		if owned {
			d.selectTransport(transportQUIC, session)
		} else {
			d.selectTransport(transportQUIC, nil)
		}
		return quicConn, nil
	}
	if owned {
		session.Close()
	}
	if session.conn.Context().Err() != nil {
		d.drop(session)
	}
	return nil, errors.Join(tcpErr, quicErr)
}

func (d *Dialer) drop(session *quicSession) {
	d.mu.Lock()
	if d.session == session {
		d.session = nil
	}
	d.mu.Unlock()
	session.Close()
}

// probe races fresh authenticated connections to the VPS. Only after choosing
// a transport do we ask the VPS to connect to the requested address.
func (d *Dialer) probe(ctx context.Context, target string) (net.Conn, error) {
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	results := make(chan dialResult, 2)
	go func() {
		session, err := protocol.DialSession(probeCtx, d.peer)
		results <- dialResult{transport: transportTCP, tcp: session, err: err}
	}()
	go func() {
		session, err := dialQUIC(probeCtx, d.peer)
		results <- dialResult{transport: transportQUIC, quic: session, err: err}
	}()

	remaining := 2
	defer func() {
		cancel()
		if remaining > 0 {
			go func(n int) {
				for range n {
					(<-results).close()
				}
			}(remaining)
		}
	}()

	var probeErr error
	for remaining > 0 {
		select {
		case <-probeCtx.Done():
			d.finishProbe(dialResult{})
			return nil, probeCtx.Err()
		case result := <-results:
			remaining--
			if probeCtx.Err() != nil {
				result.close()
				d.finishProbe(dialResult{})
				return nil, probeCtx.Err()
			}
			if result.err != nil {
				result.close()
				probeErr = errors.Join(probeErr, result.err)
				continue
			}
			cancel()
			if result.tcp != nil {
				d.tcp.addSession(result.tcp)
			}
			session := d.finishProbe(result)
			return d.dialSelected(ctx, target, result.transport, session)
		}
	}
	d.finishProbe(dialResult{})
	return nil, probeErr
}

func (d *Dialer) finishProbe(result dialResult) *quicSession {
	d.mu.Lock()
	d.probing = false
	var discard *quicSession
	if result.transport != transportUnknown {
		if result.quic != nil && d.session != nil {
			if d.session.conn.Context().Err() == nil {
				// Keep serving existing streams on the established session.
				discard, result.quic = result.quic, nil
			} else {
				discard = d.session
			}
		}
		d.setTransportLocked(result.transport, result.quic)
	}
	session := d.session
	d.mu.Unlock()
	if discard != nil {
		discard.Close()
	}
	return session
}

func (d *Dialer) selectTransport(selected transportChoice, session *quicSession) {
	d.mu.Lock()
	d.setTransportLocked(selected, session)
	d.mu.Unlock()
}

func (d *Dialer) setTransportLocked(selected transportChoice, session *quicSession) {
	if selected != transportUnknown {
		d.selected = selected
	}
	if session != nil {
		d.session = session
	}
	d.nextProbe = time.Now().Add(minProbeInterval + rand.N(maxProbeInterval-minProbeInterval))
}

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
	conn      net.Conn
	session   *quicSession
	owned     bool
	elapsed   time.Duration
	err       error
}

// Dialer 会并行探测 TCP 和 QUIC，随后在 10 到 30 分钟后重新比较两者。
type Dialer struct {
	peer protocol.Peer
	tcp  *tcpPool

	mu          sync.Mutex
	session     *quicSession
	selected    transportChoice
	probing     bool
	revision    uint64 // invalidates background probe results after a newer routing decision
	nextProbe   time.Time
	tcpLatency  time.Duration
	quicLatency time.Duration
}

func NewDialer(peer protocol.Peer) *Dialer {
	return &Dialer{peer: peer, tcp: newTCPPool(peer)}
}

func (d *Dialer) WarmUp(ctx context.Context) {
	for ctx.Err() == nil {
		d.mu.Lock()
		selected, probing := d.selected, d.probing
		d.mu.Unlock()
		if selected != transportUnknown {
			return
		}
		if !probing {
			session, err := dialQUIC(ctx, d.peer)
			if err == nil {
				d.mu.Lock()
				if ctx.Err() == nil && d.selected == transportUnknown && !d.probing {
					d.session = session
					d.selected = transportQUIC
					d.nextProbe = time.Now().Add(minProbeInterval + rand.N(maxProbeInterval-minProbeInterval))
					d.mu.Unlock()
					go func() {
						<-ctx.Done()
						d.drop(session)
					}()
					return
				}
				d.mu.Unlock()
				session.Close()
			} else if ctx.Err() == nil {
				slog.Debug("outbound/mio: quic warm-up", "err", err)
			}
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
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
		d.revision++
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
		d.selectTransport(transportTCP, nil)
		slog.Debug("outbound/mio: h3 stream failed, falling back to tcp", "err", err)
	}

	conn, tcpErr := d.tcp.dial(ctx, target)
	if tcpErr == nil || errors.Is(tcpErr, protocol.ErrConnectFailed) || ctx.Err() != nil {
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
		d.revision++
	}
	d.mu.Unlock()
	session.Close()
}

func (d *Dialer) probe(ctx context.Context, target string) (net.Conn, error) {
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeTimeout)
	results := make(chan dialResult, 2)
	go func() { results <- d.dialTCPResult(probeCtx, target) }()
	go func() { results <- d.dialQUICResult(probeCtx, target) }()

	var firstError error
	completed := make([]dialResult, 0, 2)
	for len(completed) < 2 {
		select {
		case <-ctx.Done():
			cancel()
			d.endProbe(transportUnknown, nil)
			go d.finishProbeLater(results, completed, transportUnknown, 0, cancel)
			return nil, ctx.Err()
		case result := <-results:
			completed = append(completed, result)
			if result.err != nil {
				if firstError == nil {
					firstError = result.err
				}
				continue
			}
			revision := d.endProbe(result.transport, result.session)
			go d.finishProbeLater(results, completed, result.transport, revision, cancel)
			return result.conn, nil
		}
	}
	cancel()
	d.endProbe(transportTCP, nil)
	return nil, firstError
}

func (d *Dialer) dialTCPResult(ctx context.Context, target string) dialResult {
	started := time.Now()
	conn, err := d.tcp.dial(ctx, target)
	return dialResult{transport: transportTCP, conn: conn, elapsed: time.Since(started), err: err}
}

func (d *Dialer) dialQUICResult(ctx context.Context, target string) dialResult {
	started := time.Now()
	d.mu.Lock()
	session := d.session
	d.mu.Unlock()
	owned := false
	var err error
	if session == nil || session.conn.Context().Err() != nil {
		session, err = dialQUIC(ctx, d.peer)
		if err != nil {
			return dialResult{transport: transportQUIC, elapsed: time.Since(started), err: err}
		}
		owned = true
	}
	conn, err := session.dialStream(ctx, target)
	if err != nil && owned {
		session.Close()
	}
	return dialResult{transport: transportQUIC, conn: conn, session: session, owned: owned, elapsed: time.Since(started), err: err}
}

func (d *Dialer) finishProbeLater(results <-chan dialResult, completed []dialResult, winner transportChoice, revision uint64, cancel context.CancelFunc) {
	var samples [3]dialResult
	for _, result := range completed {
		samples[result.transport] = result
	}
	for len(completed) < 2 {
		result := <-results
		samples[result.transport] = result
		completed = append(completed, result)
	}
	cancel()
	if winner == transportUnknown {
		for _, result := range samples {
			if result.conn != nil {
				result.conn.Close()
			}
			if result.owned && result.session != nil {
				result.session.Close()
			}
		}
		return
	}
	d.mu.Lock()
	var retained *quicSession
	if d.revision == revision {
		retained = d.applyProbeSamples(samples, winner)
	}
	d.mu.Unlock()

	for _, result := range samples {
		if result.err != nil || result.conn == nil || result.transport == winner {
			continue
		}
		result.conn.Close()
		if result.owned && result.session != retained {
			result.session.Close()
		}
	}
}

// applyProbeSamples runs with d.mu held and returns the session kept for reuse.
func (d *Dialer) applyProbeSamples(samples [3]dialResult, winner transportChoice) *quicSession {
	if tcp := samples[transportTCP]; tcp.err == nil {
		d.tcpLatency = smoothLatency(d.tcpLatency, tcp.elapsed)
	}
	if quic := samples[transportQUIC]; quic.err == nil {
		d.quicLatency = smoothLatency(d.quicLatency, quic.elapsed)
	}
	nextSelected := winner
	if samples[transportTCP].err == nil && samples[transportQUIC].err == nil {
		if d.quicLatency < d.tcpLatency {
			nextSelected = transportQUIC
		} else {
			nextSelected = transportTCP
		}
	}
	if nextSelected == transportQUIC && samples[transportQUIC].err == nil {
		d.session = samples[transportQUIC].session
	}
	d.selected = nextSelected
	return d.session
}

func (d *Dialer) endProbe(selected transportChoice, session *quicSession) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.probing = false
	d.setTransportLocked(selected, session)
	return d.revision
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
	d.revision++
	d.nextProbe = time.Now().Add(minProbeInterval + rand.N(maxProbeInterval-minProbeInterval))
}

func smoothLatency(previous, sample time.Duration) time.Duration {
	if previous == 0 {
		return sample
	}
	return (previous*3 + sample) / 4
}

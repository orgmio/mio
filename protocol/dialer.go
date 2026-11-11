package protocol

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/orgmio/mio/config"
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
	peer config.Peer

	mu          sync.Mutex
	session     *quicSession
	selected    transportChoice
	probing     bool
	nextProbe   time.Time
	tcpLatency  time.Duration
	quicLatency time.Duration
}

func NewDialer(peer config.Peer) *Dialer {
	return &Dialer{peer: peer}
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
				slog.Debug("quic warm-up failed", "err", err)
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
		if err == nil || errors.Is(err, ErrConnectFailed) || ctx.Err() != nil {
			return conn, err
		}
		if session.conn.Context().Err() != nil {
			d.drop(session)
		}
		d.selectTransport(transportTCP)
		slog.Debug("h3 stream failed, falling back to tcp", "err", err)
	}

	conn, tcpErr := DialTCP(ctx, d.peer, target)
	if tcpErr == nil || errors.Is(tcpErr, ErrConnectFailed) || ctx.Err() != nil {
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
			d.installSession(session)
		}
		d.selectTransport(transportQUIC)
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
			go d.finishProbeLater(results, completed, transportUnknown, cancel)
			d.endProbe(transportUnknown)
			return nil, ctx.Err()
		case result := <-results:
			completed = append(completed, result)
			if result.err != nil {
				if firstError == nil {
					firstError = result.err
				}
				continue
			}
			d.endProbe(result.transport)
			if result.transport == transportQUIC {
				d.installSession(result.session)
			}
			go d.finishProbeLater(results, completed, result.transport, cancel)
			return result.conn, nil
		}
	}
	cancel()
	d.endProbe(transportTCP)
	return nil, firstError
}

func (d *Dialer) dialTCPResult(ctx context.Context, target string) dialResult {
	started := time.Now()
	conn, err := DialTCP(ctx, d.peer, target)
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

func (d *Dialer) finishProbeLater(results <-chan dialResult, completed []dialResult, winner transportChoice, cancel context.CancelFunc) {
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
	d.mu.Unlock()

	for _, result := range samples {
		if result.err != nil || result.conn == nil || result.transport == winner {
			continue
		}
		result.conn.Close()
		if result.owned && result.transport != nextSelected {
			result.session.Close()
		}
	}
}

func (d *Dialer) endProbe(selected transportChoice) {
	d.mu.Lock()
	if selected != transportUnknown {
		d.selected = selected
	}
	d.probing = false
	d.nextProbe = time.Now().Add(minProbeInterval + rand.N(maxProbeInterval-minProbeInterval))
	d.mu.Unlock()
}

func (d *Dialer) selectTransport(selected transportChoice) {
	d.mu.Lock()
	d.selected = selected
	d.nextProbe = time.Now().Add(minProbeInterval + rand.N(maxProbeInterval-minProbeInterval))
	d.mu.Unlock()
}

func (d *Dialer) installSession(session *quicSession) {
	d.mu.Lock()
	d.session = session
	d.mu.Unlock()
}

func smoothLatency(previous, sample time.Duration) time.Duration {
	if previous == 0 {
		return sample
	}
	return (previous*3 + sample) / 4
}

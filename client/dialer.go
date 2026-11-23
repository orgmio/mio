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
	minFirstProbeDelay = time.Second
	maxFirstProbeDelay = 10 * time.Second
	minProbeInterval   = 10 * time.Minute
	maxProbeInterval   = 30 * time.Minute
	probeTimeout       = 25 * time.Second
	quicSlowThreshold  = 2 * time.Second
)

type transportChoice uint8

const (
	transportTCP transportChoice = iota
	transportQUIC
)

type dialResult struct {
	transport transportChoice
	tcp       *protocol.Session
	quic      *quicSession
	conn      net.Conn
	err       error
}

func (r dialResult) close() {
	if r.tcp != nil {
		r.tcp.Close()
	}
	if r.quic != nil {
		r.quic.Close()
	}
	if r.conn != nil {
		r.conn.Close()
	}
}

// Dialer starts on TCP and periodically compares fresh TCP and QUIC sessions.
type Dialer struct {
	peer   protocol.Peer
	tcp    *tcpPool
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	selected   transportChoice
	quic       *quicSession
	probeTimer *time.Timer
	generation uint64
	recovery   chan struct{}
}

func NewDialer(peer protocol.Peer) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Dialer{peer: peer, tcp: newTCPPool(ctx, peer), ctx: ctx, cancel: cancel}
}

func (d *Dialer) Dial(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	defer cancel()
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}

	d.mu.Lock()
	selected, quic, generation := d.selected, d.quic, d.generation
	d.mu.Unlock()

	conn, err := d.dialSelected(ctx, target, selected, quic)
	if err == nil || errors.Is(err, protocol.ErrConnectFailed) {
		d.mu.Lock()
		if d.probeTimer == nil && d.recovery == nil && d.ctx.Err() == nil {
			d.scheduleProbeLocked(minFirstProbeDelay, maxFirstProbeDelay)
		}
		d.mu.Unlock()
		return conn, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	slog.Debug("outbound/mio: selected transport failed, racing TCP and QUIC", "err", err)
	return d.recover(ctx, target, generation, err)
}

func (d *Dialer) dialSelected(ctx context.Context, target string, selected transportChoice, quic *quicSession) (net.Conn, error) {
	if selected == transportQUIC {
		quickCtx, cancel := context.WithTimeout(ctx, quicSlowThreshold)
		defer cancel()
		return quic.dialStream(quickCtx, target)
	}
	return d.tcp.dial(ctx, target)
}

func (d *Dialer) recover(ctx context.Context, target string, generation uint64, previousErr error) (net.Conn, error) {
	d.mu.Lock()
	if d.recovery == nil && generation != d.generation {
		selected, quic := d.selected, d.quic
		d.mu.Unlock()
		conn, err := d.dialSelected(ctx, target, selected, quic)
		if err == nil || errors.Is(err, protocol.ErrConnectFailed) || ctx.Err() != nil {
			return conn, err
		}
		previousErr = err
		d.mu.Lock()
	}
	if d.recovery != nil {
		done := d.recovery
		d.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		d.mu.Lock()
		selected, quic := d.selected, d.quic
		d.mu.Unlock()
		return d.dialSelected(ctx, target, selected, quic)
	}
	if d.ctx.Err() != nil {
		d.mu.Unlock()
		return nil, d.ctx.Err()
	}
	done := make(chan struct{})
	d.recovery = done
	d.generation++
	if d.probeTimer != nil {
		d.probeTimer.Stop()
	}
	d.mu.Unlock()

	result, err := d.race(ctx, target, true)

	d.mu.Lock()
	var retired *quicSession
	if d.ctx.Err() != nil {
		if err == nil {
			err = d.ctx.Err()
			defer result.close()
		}
	} else {
		minimum, maximum := minProbeInterval, maxProbeInterval
		if d.probeTimer == nil {
			minimum, maximum = minFirstProbeDelay, maxFirstProbeDelay
		}
		if err == nil {
			retired = d.selectLocked(result)
		}
		if err == nil || d.probeTimer != nil {
			d.scheduleProbeLocked(minimum, maximum)
		}
	}
	d.recovery = nil
	close(done)
	d.mu.Unlock()
	if retired != nil {
		retired.retire()
	}
	if err != nil {
		return nil, errors.Join(previousErr, err)
	}
	return result.conn, nil
}

func (d *Dialer) scheduleProbeLocked(minimum, maximum time.Duration) {
	d.generation++
	generation := d.generation
	d.probeTimer = time.AfterFunc(minimum+rand.N(maximum-minimum), func() { d.probe(generation) })
}

func (d *Dialer) probe(generation uint64) {
	d.mu.Lock()
	current := generation == d.generation && d.ctx.Err() == nil
	d.mu.Unlock()
	if !current {
		return
	}
	result, err := d.race(d.ctx, "", false)
	d.mu.Lock()
	if generation != d.generation || d.ctx.Err() != nil {
		d.mu.Unlock()
		result.close()
		return
	}
	var retired *quicSession
	if err == nil {
		retired = d.selectLocked(result)
	}
	d.scheduleProbeLocked(minProbeInterval, maxProbeInterval)
	d.mu.Unlock()
	if retired != nil {
		retired.retire()
	}
}

// Periodic probes only authenticate. Recovery also waits for a successful
// target reply, so it can distinguish a slow QUIC stream from a slow handshake.
func (d *Dialer) race(ctx context.Context, target string, requestTarget bool) (dialResult, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	results := make(chan dialResult, 2)
	for _, transport := range []transportChoice{transportTCP, transportQUIC} {
		go func() {
			result := dialResult{transport: transport}
			if transport == transportTCP {
				result.tcp, result.err = protocol.DialSession(ctx, d.peer)
				if requestTarget && result.err == nil {
					result.conn, result.err = result.tcp.Dial(ctx, target)
				}
			} else {
				result.quic, result.err = dialQUIC(ctx, d.peer)
				if requestTarget && result.err == nil {
					result.conn, result.err = result.quic.dialStream(ctx, target)
				}
			}
			results <- result
		}()
	}
	remaining := 2
	defer func() {
		cancel()
		if remaining > 0 {
			go func() {
				for range remaining {
					(<-results).close()
				}
			}()
		}
	}()

	var raceErr error
	for remaining > 0 {
		select {
		case <-ctx.Done():
			return dialResult{}, ctx.Err()
		case result := <-results:
			remaining--
			if ctx.Err() != nil {
				result.close()
				return dialResult{}, ctx.Err()
			}
			if result.err == nil {
				return result, nil
			}
			result.close()
			raceErr = errors.Join(raceErr, result.err)
		}
	}
	return dialResult{}, raceErr
}

// selectLocked installs the winner for new requests and returns the previous
// QUIC session so its existing streams can finish.
func (d *Dialer) selectLocked(result dialResult) *quicSession {
	if result.tcp != nil {
		d.tcp.addSession(result.tcp)
	}
	old := d.quic
	d.selected, d.quic = result.transport, result.quic
	path := "TCP"
	if result.quic != nil {
		path = "QUIC"
	}
	slog.Debug("outbound/mio: transport race winner", "transport", path)
	return old
}

// Close stops background probes and closes the current sessions.
func (d *Dialer) Close() {
	d.cancel()
	d.mu.Lock()
	if d.probeTimer != nil {
		d.probeTimer.Stop()
	}
	quic := d.quic
	d.mu.Unlock()
	if quic != nil {
		quic.Close()
	}
	d.tcp.close()
}

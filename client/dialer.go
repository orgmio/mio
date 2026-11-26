package client

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/orgmio/mio/protocol"
)

const (
	minFirstProbeDelay = time.Second
	maxFirstProbeDelay = 10 * time.Second
	minProbeInterval   = 10 * time.Minute
	maxProbeInterval   = 30 * time.Minute
	dialTimeLimit      = 25 * time.Second
	minFallbackDelay   = 250 * time.Millisecond
	maxFallbackDelay   = time.Second
	probeHeadStart     = 25 * time.Millisecond
)

type transportChoice uint8

const (
	transportTCP transportChoice = iota
	transportQUIC
)

func (t transportChoice) String() string {
	if t == transportQUIC {
		return "QUIC"
	}
	return "TCP"
}

type dialResult struct {
	transport transportChoice
	conn      net.Conn
	elapsed   time.Duration
	err       error
}

type quicDialAttempt struct {
	done    chan struct{}
	session *quicSession
	err     error
}

// Dialer 最初使用 TCP，让首选传输先尝试打开请求所需的流。
// 只有备用传输先成功打开流时，才会采用备用传输。
type Dialer struct {
	peer       protocol.Peer
	tcp        *tcpPool
	enableQUIC bool
	ctx        context.Context
	cancel     context.CancelFunc
	early      atomic.Bool

	mu         sync.Mutex
	preferred  transportChoice
	latency    time.Duration
	nextProbe  time.Time
	generation uint64
	quic       *quicSession
	quicDial   *quicDialAttempt
}

func NewDialer(peer protocol.Peer) *Dialer {
	return newDialer(peer, true)
}

func newDialer(peer protocol.Peer, enableQUIC bool) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Dialer{peer: peer, tcp: newTCPPool(ctx, peer), enableQUIC: enableQUIC, ctx: ctx, cancel: cancel}
}

func (d *Dialer) Dial(ctx context.Context, target string) (net.Conn, error) {
	return d.dial(ctx, protocol.StreamRequest{Target: target})
}

func (d *Dialer) dial(ctx context.Context, request protocol.StreamRequest) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeLimit)
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	defer cancel()
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}
	if !d.enableQUIC {
		return d.tcp.dial(ctx, request, d.early.Load())
	}

	d.mu.Lock()
	preferred, generation := d.preferred, d.generation
	delay := minFallbackDelay
	if d.latency != 0 {
		delay = min(max(2*d.latency, minFallbackDelay), maxFallbackDelay)
	}
	if !d.nextProbe.IsZero() && time.Now().After(d.nextProbe) {
		delay = probeHeadStart
		d.scheduleProbe(minProbeInterval, maxProbeInterval)
	}
	d.mu.Unlock()

	backup := transportQUIC
	if preferred == transportQUIC {
		backup = transportTCP
	}
	results := make(chan dialResult)
	start := func(transport transportChoice) {
		go func() {
			started := time.Now()
			conn, err := d.dialStream(ctx, transport, request)
			result := dialResult{transport: transport, conn: conn, elapsed: time.Since(started), err: err}
			select {
			case results <- result:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}

	start(preferred)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	backupTimer := timer.C
	pending := 1
	var dialErr error
	for pending > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-backupTimer:
			slog.DebugContext(ctx, "outbound/mio: trying alternate transport", "preferred", preferred, "backup", backup, "elapsed", delay)
			start(backup)
			pending++
			backupTimer = nil
		case result := <-results:
			pending--
			if ctx.Err() != nil {
				if result.conn != nil {
					result.conn.Close()
				}
				return nil, ctx.Err()
			}
			if result.err == nil {
				d.recordSuccess(ctx, generation, result)
				return result.conn, nil
			}
			if result.transport == preferred && errors.Is(result.err, protocol.ErrConnectFailed) {
				return nil, result.err
			}
			dialErr = errors.Join(dialErr, result.err)
			if backupTimer != nil {
				slog.InfoContext(ctx, "outbound/mio: preferred transport failed, trying alternate", "transport", preferred, "err", result.err)
				timer.Stop()
				start(backup)
				pending++
				backupTimer = nil
			}
		}
	}
	return nil, dialErr
}

// 调用方须持有 d.mu 锁。
func (d *Dialer) scheduleProbe(minimum, maximum time.Duration) {
	d.nextProbe = time.Now().Add(minimum + rand.N(maximum-minimum))
}

func (d *Dialer) recordSuccess(ctx context.Context, generation uint64, result dialResult) {
	d.mu.Lock()
	if generation != d.generation || d.ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	changed := d.preferred != result.transport
	switch {
	case changed:
		d.preferred = result.transport
		d.generation++
		d.latency = result.elapsed
		d.scheduleProbe(minProbeInterval, maxProbeInterval)
	case d.latency == 0:
		d.latency = result.elapsed
		d.scheduleProbe(minFirstProbeDelay, maxFirstProbeDelay)
	default:
		d.latency += (result.elapsed - d.latency) / 4
	}
	d.mu.Unlock()
	if changed {
		slog.InfoContext(ctx, "outbound/mio: transport selected", "transport", result.transport, "elapsed", result.elapsed)
	}
}

func (d *Dialer) dialStream(ctx context.Context, transport transportChoice, request protocol.StreamRequest) (net.Conn, error) {
	if transport == transportTCP {
		return d.tcp.dial(ctx, request, d.early.Load())
	}
	var streamErr error
	for range 2 {
		session, err := d.quicSession(ctx)
		if err != nil {
			return nil, err
		}
		if d.early.Load() {
			session.early.probe(session.conn.Context(), session.dialStream)
		}
		conn, err := session.dialStream(ctx, request)
		if err == nil || errors.Is(err, protocol.ErrConnectFailed) || ctx.Err() != nil || session.conn.Context().Err() == nil {
			return conn, err
		}
		streamErr = err
	}
	return nil, streamErr
}

func (d *Dialer) quicSession(ctx context.Context) (*quicSession, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.quic != nil && d.quic.conn.Context().Err() == nil {
		session := d.quic
		d.mu.Unlock()
		return session, nil
	}
	attempt := d.quicDial
	if attempt == nil && d.ctx.Err() == nil {
		attempt = &quicDialAttempt{done: make(chan struct{})}
		d.quicDial = attempt
		go d.connectQUIC(attempt)
	}
	d.mu.Unlock()
	if attempt == nil {
		return nil, d.ctx.Err()
	}
	select {
	case <-attempt.done:
		return attempt.session, attempt.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *Dialer) connectQUIC(attempt *quicDialAttempt) {
	session, err := dialQUIC(d.ctx, d.peer)
	d.mu.Lock()
	d.quicDial = nil
	if err == nil && d.ctx.Err() == nil {
		d.quic = session
		attempt.session = session
	} else if err == nil {
		err = d.ctx.Err()
	}
	attempt.err = err
	close(attempt.done)
	d.mu.Unlock()
	if err != nil && session != nil {
		session.Close()
	}
}

// Close 取消尚未完成的拨号，并关闭两种传输。
func (d *Dialer) Close() {
	d.cancel()
	d.mu.Lock()
	quic := d.quic
	d.mu.Unlock()
	if quic != nil {
		quic.Close()
	}
	d.tcp.close()
}

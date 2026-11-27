package client

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/protocol"
)

const dialTimeLimit = 25 * time.Second

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
	peer      protocol.Peer
	tcp       *tcpPool
	transport config.Transport
	ctx       context.Context
	cancel    context.CancelFunc
	early     atomic.Bool

	mu       sync.Mutex
	policy   transportPolicy
	quic     *quicSession
	quicDial *quicDialAttempt
}

func NewDialer(peer protocol.Peer) *Dialer {
	return newDialer(peer, config.TransportAuto)
}

func newDialer(peer protocol.Peer, transport config.Transport) *Dialer {
	ctx, cancel := context.WithCancel(context.Background())
	return &Dialer{peer: peer, tcp: newTCPPool(ctx, peer), transport: transport, ctx: ctx, cancel: cancel}
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
	switch d.transport {
	case config.TransportTCP:
		return d.dialStream(ctx, transportTCP, request)
	case config.TransportUDP:
		return d.dialStream(ctx, transportQUIC, request)
	}

	d.mu.Lock()
	plan := d.policy.plan(time.Now())
	d.mu.Unlock()
	result, err := raceTransports(ctx, plan, func(ctx context.Context, transport transportChoice) (net.Conn, error) {
		return d.dialStream(ctx, transport, request)
	})
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	changed := d.ctx.Err() == nil && d.policy.recordSuccess(time.Now(), plan.generation, result.transport, result.elapsed)
	d.mu.Unlock()
	if changed {
		slog.InfoContext(ctx, "outbound/mio: transport selected", "transport", result.transport, "elapsed", result.elapsed)
	}
	return result.conn, nil
}

func raceTransports(ctx context.Context, plan dialPlan, open func(context.Context, transportChoice) (net.Conn, error)) (dialResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan dialResult)
	start := func(transport transportChoice) {
		go func() {
			started := time.Now()
			conn, err := open(ctx, transport)
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

	start(plan.preferred)
	timer := time.NewTimer(plan.delay)
	defer timer.Stop()
	backupTimer := timer.C
	pending := 1
	var dialErr error
	for pending > 0 {
		select {
		case <-ctx.Done():
			return dialResult{}, ctx.Err()
		case <-backupTimer:
			slog.DebugContext(ctx, "outbound/mio: trying alternate transport", "preferred", plan.preferred, "backup", plan.backup, "elapsed", plan.delay)
			start(plan.backup)
			pending++
			backupTimer = nil
		case result := <-results:
			pending--
			if ctx.Err() != nil {
				if result.conn != nil {
					result.conn.Close()
				}
				return dialResult{}, ctx.Err()
			}
			if result.err == nil {
				return result, nil
			}
			if result.transport == plan.preferred && errors.Is(result.err, protocol.ErrConnectFailed) {
				return dialResult{}, result.err
			}
			dialErr = errors.Join(dialErr, result.err)
			if backupTimer != nil {
				slog.InfoContext(ctx, "outbound/mio: preferred transport failed, trying alternate", "transport", plan.preferred, "err", result.err)
				timer.Stop()
				start(plan.backup)
				pending++
				backupTimer = nil
			}
		}
	}
	return dialResult{}, dialErr
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

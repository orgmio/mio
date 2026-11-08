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
	minUpgradeDelay = 1 * time.Second
	maxUpgradeDelay = 30 * time.Second
	maxBackoff      = time.Hour
)

// Dialer 先走 TCP；第一次成功后随机等待 1 到 30 秒再在后台升级到 QUIC，之后的新连接走 QUIC stream。
// 已有的 TCP 连接不迁移，QUIC 不可用时回退 TCP 并退避重试。
type Dialer struct {
	peer config.Peer

	mu        sync.Mutex
	session   *quicSession
	scheduled bool
	failures  int
}

func NewDialer(peer config.Peer) *Dialer {
	return &Dialer{peer: peer}
}

func (d *Dialer) Dial(ctx context.Context, target string) (net.Conn, error) {
	d.mu.Lock()
	session := d.session
	d.mu.Unlock()

	if session != nil {
		conn, err := session.dialStream(ctx, target)
		if err == nil {
			return conn, nil
		}
		if errors.Is(err, ErrConnectFailed) {
			return nil, err
		}
		slog.Debug("h3 stream failed, fall back to tcp", "err", err)
		if session.conn.Context().Err() != nil {
			d.drop(session)
		}
	}

	conn, err := DialTCP(ctx, d.peer, target)
	if err == nil {
		d.scheduleUpgrade()
	}
	return conn, err
}

func (d *Dialer) drop(session *quicSession) {
	d.mu.Lock()
	if d.session == session {
		d.session = nil
	}
	d.mu.Unlock()
	session.Close()
}

func (d *Dialer) scheduleUpgrade() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.session != nil || d.scheduled {
		return
	}
	d.scheduled = true

	delay := minUpgradeDelay + rand.N(maxUpgradeDelay-minUpgradeDelay)
	if d.failures > 0 {
		delay += min(time.Minute<<(d.failures-1), maxBackoff)
	}
	time.AfterFunc(delay, d.upgrade)
}

func (d *Dialer) upgrade() {
	session, err := dialQUIC(context.Background(), d.peer)

	d.mu.Lock()
	d.scheduled = false
	if err != nil {
		d.failures = min(d.failures+1, 16)
		d.mu.Unlock()
		slog.Debug("h3 upgrade failed", "err", err)
		return
	}
	d.failures = 0
	d.session = session
	d.mu.Unlock()
	slog.Info("upgraded to h3", "server", d.peer.Server)

	go func() {
		<-session.done()
		d.drop(session)
	}()
}

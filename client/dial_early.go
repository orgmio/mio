package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/protocol"
)

type earlySupport struct {
	once      sync.Once
	confirmed atomic.Bool
}

func (s *earlySupport) probe(ctx context.Context, dial func(context.Context, protocol.StreamRequest) (net.Conn, error)) {
	s.once.Do(func() {
		go func() {
			ctx, cancel := context.WithTimeout(ctx, replyTimeout)
			defer cancel()
			conn, err := dial(ctx, protocol.StreamRequest{ProbeEarlyTCP: true})
			if err == nil {
				s.confirmed.Store(true)
				conn.Close()
			}
		}()
	})
}

type earlyConn struct {
	net.Conn
	readMu        sync.Mutex
	deadlineMu    sync.Mutex
	replyDeadline time.Time
	readDeadline  time.Time
	replyErr      error
	onFailure     func()
}

func (c *earlyConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.readReply(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *earlyConn) readReply() error {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.replyDeadline.IsZero() {
		return c.replyErr
	}
	err := protocol.ReadReply(c.Conn)
	// 调用方可重新设置较短的截止时间，然后重试读取应答。
	if errors.Is(err, os.ErrDeadlineExceeded) && time.Now().Before(c.replyDeadline) {
		return err
	}
	c.deadlineMu.Lock()
	c.replyDeadline = time.Time{}
	c.replyErr = err
	c.Conn.SetReadDeadline(c.readDeadline)
	c.deadlineMu.Unlock()
	if err != nil {
		if !errors.Is(err, net.ErrClosed) && !errors.Is(err, protocol.ErrConnectFailed) {
			c.onFailure()
		}
		c.Conn.Close()
	}
	return err
}

func (c *earlyConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.readDeadline = t
	if !c.replyDeadline.IsZero() && (t.IsZero() || c.replyDeadline.Before(t)) {
		t = c.replyDeadline
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *earlyConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.Conn.SetWriteDeadline(t))
}

func (c *earlyConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (c *earlyConn) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(c.Conn, r)
}

func (c *earlyConn) WriteTo(w io.Writer) (int64, error) {
	if err := c.readReply(); err != nil {
		return 0, err
	}
	if wt, ok := c.Conn.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return io.Copy(w, c.Conn)
}

// DialEarly 在此前选定且支持提前发送 TCP 数据的会话上，允许在收到目标连接应答前写入。
// 连接目标时发生的错误可能在调用 Read 时返回。
func (d *Dialer) DialEarly(ctx context.Context, target string) (net.Conn, error) {
	d.early.Store(true)
	d.mu.Lock()
	preferred, session, generation := d.policy.preferred, d.quic, d.policy.generation
	if d.transport == config.TransportUDP {
		preferred = transportQUIC
	}
	selected := d.transport != config.TransportAuto || d.policy.latency > 0
	probeDue := !d.policy.nextProbe.IsZero() && !time.Now().Before(d.policy.nextProbe)
	d.mu.Unlock()
	if d.ctx.Err() != nil || ctx.Err() != nil || !selected || probeDue {
		return d.Dial(ctx, target)
	}

	openCtx, cancel := context.WithTimeout(ctx, replyTimeout)
	defer cancel()
	var conn net.Conn
	var err error
	if preferred == transportTCP {
		if session := d.tcp.earlySession(); session != nil {
			conn, err = session.DialEarly(openCtx, target)
		}
	} else if session != nil && session.early.confirmed.Load() && session.conn.Context().Err() == nil {
		conn, err = session.openStream(openCtx, protocol.StreamRequest{Target: target}, true)
	}
	if conn == nil || err != nil {
		return d.Dial(ctx, target)
	}
	early := &earlyConn{
		Conn: conn, replyDeadline: time.Now().Add(replyTimeout),
		onFailure: func() {
			d.mu.Lock()
			if d.transport == config.TransportAuto && generation == d.policy.generation && preferred == d.policy.preferred {
				d.policy.nextProbe = time.Now()
			}
			d.mu.Unlock()
		},
	}
	conn.SetReadDeadline(early.replyDeadline)
	return early, nil
}

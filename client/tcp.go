package client

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol"
)

const (
	// maxSessionStreams 是一条 TCP 连接上同时承载的代理连接数上限，超过后再开一条新连接。
	maxSessionStreams = 100
	// 一条 TCP 连接上没有任何代理连接后，过 minSessionIdle 到 maxSessionIdle 之间的随机时长就关闭它。
	minSessionIdle = 4 * time.Minute
	maxSessionIdle = 6 * time.Minute
)

// tcpPool 让所有代理连接尽量复用同一条到服务端的 TCP 连接，就像浏览器对同一个 HTTP/2 站点只开一条连接。
type tcpPool struct {
	peer protocol.Peer

	mu       sync.Mutex
	sessions []*protocol.Session
	dialing  *dialAttempt // 有协程正在新建连接时非 nil
}

// dialAttempt 是一次正在进行的新建连接，done 关闭后 err 即为结果。
type dialAttempt struct {
	done chan struct{}
	err  error
}

func newTCPPool(peer protocol.Peer) *tcpPool {
	return &tcpPool{peer: peer}
}

// dial 在一条可用的连接上请求服务端连接 target；连接在途中断开时换一条新的再试一次。
func (p *tcpPool) dial(ctx context.Context, target string) (conn net.Conn, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		var session *protocol.Session
		session, err = p.session(ctx)
		if err != nil {
			return nil, err
		}
		conn, err = session.Dial(ctx, target)
		if err == nil || errors.Is(err, protocol.ErrConnectFailed) || ctx.Err() != nil {
			return conn, err
		}
		select {
		case <-session.Done():
		default:
			// 连接本身还好，是这一条流出了问题，重试也没用。
			return nil, err
		}
	}
	return nil, err
}

// session 返回一条还能再开流的连接，没有就新建一条。同一时刻只有一个协程在新建，其余的等它建好后复用；
// 新建失败时等待者直接拿到同一个错误，不会排着队一个接一个地重试。
func (p *tcpPool) session(ctx context.Context) (*protocol.Session, error) {
	for {
		p.mu.Lock()
		alive := p.sessions[:0]
		for _, session := range p.sessions {
			select {
			case <-session.Done():
			default:
				alive = append(alive, session)
			}
		}
		clear(p.sessions[len(alive):])
		p.sessions = alive
		for _, session := range p.sessions {
			if session.NumStreams() < maxSessionStreams {
				p.mu.Unlock()
				return session, nil
			}
		}
		if attempt := p.dialing; attempt != nil {
			p.mu.Unlock()
			select {
			case <-attempt.done:
				if attempt.err != nil {
					return nil, attempt.err
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		attempt := &dialAttempt{done: make(chan struct{})}
		p.dialing = attempt
		p.mu.Unlock()

		// 不用调用方的 ctx：等待者会共享这次结果，不能因为发起者被取消就让大家一起失败。
		// DialSession 自带握手时限，不会一直卡住。
		session, err := protocol.DialSession(context.WithoutCancel(ctx), p.peer)
		p.mu.Lock()
		p.dialing = nil
		if err == nil {
			session.SetIdleTimeout(minSessionIdle + rand.N(maxSessionIdle-minSessionIdle))
			p.sessions = append(p.sessions, session)
		}
		attempt.err = err
		p.mu.Unlock()
		close(attempt.done)
		return session, err
	}
}

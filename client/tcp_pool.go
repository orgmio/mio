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
	// 一条 TCP 连接上没有任何代理连接后，过 minSessionIdle 到 maxSessionIdle 之间的随机时长就关闭它。
	minSessionIdle = 4 * time.Minute
	maxSessionIdle = 6 * time.Minute
)

// tcpPool 让所有代理连接尽量复用同一条到服务端的 TCP 连接，就像浏览器对同一个 HTTP/2 站点只开一条连接。
type tcpPool struct {
	peer protocol.Peer
	ctx  context.Context

	mu       sync.Mutex
	sessions []*protocol.Session
	dialing  *dialAttempt // 有协程正在新建连接时非 nil
}

// dialAttempt 是一次正在进行的新建连接，done 关闭后 err 即为结果。
type dialAttempt struct {
	done chan struct{}
	err  error
}

func newTCPPool(ctx context.Context, peer protocol.Peer) *tcpPool {
	return &tcpPool{peer: peer, ctx: ctx}
}

// addSession makes the session established by a transport probe available for requests.
func (p *tcpPool) addSession(session *protocol.Session) {
	p.mu.Lock()
	if p.ctx.Err() == nil {
		session.SetIdleTimeout(minSessionIdle + rand.N(maxSessionIdle-minSessionIdle))
		p.sessions = append(p.sessions, session)
	} else {
		session.Close()
	}
	p.mu.Unlock()
}

func (p *tcpPool) close() {
	p.mu.Lock()
	sessions := p.sessions
	p.sessions = nil
	p.mu.Unlock()
	for _, session := range sessions {
		session.Close()
	}
}

// dial 在一条可用的连接上请求服务端连接 target；连接在途中断开时换一条新的再试一次。
func (p *tcpPool) dial(ctx context.Context, request protocol.StreamRequest) (conn net.Conn, err error) {
	for attempt := 0; attempt < 2; {
		var session *protocol.Session
		session, err = p.session(ctx)
		if err != nil {
			return nil, err
		}
		conn, err = session.DialRequest(ctx, request)
		if errors.Is(err, protocol.ErrStreamLimit) {
			continue
		}
		attempt++
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if err := p.ctx.Err(); err != nil {
			p.mu.Unlock()
			return nil, err
		}
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
		for i := len(p.sessions) - 1; i >= 0; i-- {
			session := p.sessions[i]
			if session.NumStreams() < protocol.MaxSessionStreams {
				p.mu.Unlock()
				return session, nil
			}
		}
		attempt := p.dialing
		if attempt == nil {
			attempt = &dialAttempt{done: make(chan struct{})}
			p.dialing = attempt
			// 等待者共享握手结果，各自可以取消等待。
			go p.connect(attempt)
		}
		p.mu.Unlock()
		select {
		case <-attempt.done:
			if attempt.err != nil {
				return nil, attempt.err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (p *tcpPool) connect(attempt *dialAttempt) {
	session, err := protocol.DialSession(p.ctx, p.peer)
	if err == nil {
		p.addSession(session)
	}
	p.mu.Lock()
	p.dialing = nil
	attempt.err = err
	close(attempt.done)
	p.mu.Unlock()
}

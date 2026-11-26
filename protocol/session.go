package protocol

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MaxSessionStreams 限制单个 TCP 会话中的并发流数量。
const MaxSessionStreams = 100

// ErrSessionClosed 表示会话已经关闭，不能再打开或接受流。
var ErrSessionClosed = errors.New("session closed")

// ErrStreamLimit 表示会话中的流数量已达到 MaxSessionStreams。
var ErrStreamLimit = errors.New("session stream limit reached")

// Session 是一条 mio 加密连接：每个帧封装为一条 TLS Application Data 记录，用 AES-256-GCM 加密，
// 5 字节记录头作为附加数据参与认证，nonce 为记录序号。一个 Session 上可以同时有多条流，
// 每条流是一个 net.Conn。
//
// Session 的方法都可以并发调用。
type Session struct {
	conn   net.Conn
	reader *bufio.Reader
	client bool

	// 发送方向：writeMu 保证记录按序号依次写出。
	writeMu   chan struct{}
	send      cipher.AEAD
	sendSeq   uint64
	sendNonce [gcmNonceSize]byte
	writeBuf  []byte // 整条记录在这里拼好并原地加密，跨帧复用

	// 接收方向：握手阶段由握手协程使用，之后只由 readLoop 使用。
	recv      cipher.AEAD
	recvSeq   uint64
	recvNonce [gcmNonceSize]byte
	readBuf   []byte
	// lastRecv 是最近一次收到对端记录的时间（UnixNano），用来判断连接是否已经悄悄断了。
	lastRecv atomic.Int64

	mu          sync.Mutex
	streams     map[uint32]*stream
	unopened    int    // 客户端已 Open、还没发过数据（因而还没有编号）的流的数量
	nextID      uint32 // 客户端下一条流的编号
	lastPeerID  uint32 // 服务端见过的最大流编号
	err         error  // 非 nil 表示会话已关闭
	idleTimeout time.Duration
	idleUntil   time.Time
	idleTimer   *time.Timer // 整个会话只有这一个空闲定时器，每次变空闲时重置

	sendCredit   int
	recvCredit   int
	recvConsumed int
	creditReady  chan struct{}
	windowReady  chan struct{}

	accept chan *stream
	reject chan uint32
	done   chan struct{}
}

func newSession(conn net.Conn, reader *bufio.Reader, send, recv cipher.AEAD, isClient bool) *Session {
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	return &Session{
		conn:        conn,
		writeMu:     make(chan struct{}, 1),
		reader:      reader,
		client:      isClient,
		send:        send,
		recv:        recv,
		streams:     make(map[uint32]*stream),
		nextID:      1,
		sendCredit:  SessionWindow,
		recvCredit:  SessionWindow,
		creditReady: make(chan struct{}),
		windowReady: make(chan struct{}, 1),
		accept:      make(chan *stream, MaxSessionStreams),
		reject:      make(chan uint32, MaxSessionStreams),
		done:        make(chan struct{}),
	}
}

// rekey 换成新的密钥并把两个方向的序号清零，只在握手阶段、start 之前调用。
func (s *Session) rekey(send, recv cipher.AEAD) {
	s.send, s.recv = send, recv
	s.sendSeq, s.recvSeq = 0, 0
}

func (s *Session) start() {
	go s.writeControlFrames()
	go s.readLoop()
}

// Open 打开一条新的流，只有客户端可以调用。流在第一次 Write 时才取得编号，对端也是在那时才知道它。
func (s *Session) Open() (net.Conn, error) {
	if !s.client {
		return nil, errors.New("only the client can open streams")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if len(s.streams)+s.unopened >= MaxSessionStreams {
		return nil, ErrStreamLimit
	}
	s.unopened++
	return newStream(s, 0), nil
}

// Accept 等待并返回客户端打开的下一条流，只有服务端会收到流。会话关闭后返回错误。
func (s *Session) Accept() (net.Conn, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.done:
		return nil, s.closeError()
	}
}

// Close 关闭会话和底层连接，其上所有的流随之失效。
func (s *Session) Close() error {
	s.closeWithError(ErrSessionClosed)
	return nil
}

// Done 返回的通道 在会话关闭后关闭。
func (s *Session) Done() <-chan struct{} { return s.done }

// NumStreams 返回当前打开着的流的数量。
func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams) + s.unopened
}

func (s *Session) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *Session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// SetIdleTimeout 让会话在没有任何流的状态持续 d 之后自动关闭；d 为 0 时不自动关闭（默认）。
func (s *Session) SetIdleTimeout(d time.Duration) {
	s.mu.Lock()
	s.idleTimeout = d
	if d <= 0 && s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	s.armIdleTimer()
	s.mu.Unlock()
}

// armIdleTimer 在没有流时（重新）开始空闲计时，调用时需持有 s.mu。
// 有流打开时不必停掉定时器：到期时会再检查一次，那时有流就什么都不做；流全部关闭时会重新从头计时。
func (s *Session) armIdleTimer() {
	if s.idleTimeout <= 0 || len(s.streams)+s.unopened > 0 || s.err != nil {
		return
	}
	s.idleUntil = time.Now().Add(s.idleTimeout)
	if s.idleTimer == nil {
		s.idleTimer = time.AfterFunc(s.idleTimeout, s.idleExpired)
		return
	}
	s.idleTimer.Reset(s.idleTimeout)
}

func (s *Session) idleExpired() {
	s.mu.Lock()
	if s.idleTimeout <= 0 || len(s.streams)+s.unopened != 0 || time.Now().Before(s.idleUntil) {
		s.mu.Unlock()
		return
	}
	closed := s.markClosedLocked(ErrSessionClosed)
	s.mu.Unlock()
	if closed {
		s.conn.Close()
	}
}

// removeStream 在流关闭时把它从会话里去掉；id 为 0 表示它还没有编号。
func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	if id == 0 {
		s.unopened--
	} else {
		delete(s.streams, id)
	}
	s.armIdleTimer()
	s.mu.Unlock()
}

func (s *Session) closeError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) closeWithError(err error) {
	s.mu.Lock()
	closed := s.markClosedLocked(err)
	s.mu.Unlock()
	if closed {
		s.conn.Close()
	}
}

func (s *Session) markClosedLocked(err error) bool {
	if s.err != nil {
		return false
	}
	if !errors.Is(err, ErrSessionClosed) {
		err = fmt.Errorf("%w: %w", ErrSessionClosed, err)
	}
	s.err = err
	s.streams = nil
	if s.idleTimer != nil {
		s.idleTimer.Stop()
	}
	close(s.done)
	return true
}

// readLoop 读取记录并分发给对应的流，读失败时关闭会话。
// 它从不等待写操作：流的接收缓冲受流量控制约束，所以分发不会阻塞，对端的发送也就不会被卡死。
func (s *Session) readLoop() {
	for {
		typ, id, payload, err := s.readFrame(false)
		if err != nil {
			s.closeWithError(err)
			return
		}
		switch typ {
		case FrameData:
			if !s.takeReceiveCredit(len(payload)) {
				s.closeWithError(errors.New("peer exceeded the session window"))
				return
			}
			if st := s.lookup(id, true); st == nil {
				s.releaseReceiveCredit(len(payload))
			} else if err := st.receive(payload); err != nil {
				s.closeWithError(err)
				return
			}
		case FrameClose:
			if st := s.lookup(id, false); st != nil {
				st.receiveClose()
			}
		case FrameReset:
			if st := s.lookup(id, false); st != nil {
				st.receiveReset()
			}
		case FrameWindow:
			if len(payload) != 4 {
				s.closeWithError(errors.New("invalid window frame"))
				return
			}
			increment := binary.BigEndian.Uint32(payload)
			switch {
			case id == 0:
				if increment == 0 || increment > SessionWindow || !s.addSendCredit(int(increment)) {
					s.closeWithError(errors.New("invalid session window increment"))
					return
				}
			default:
				if st := s.lookup(id, false); st != nil &&
					(increment == 0 || increment > StreamWindow || !st.addCredit(int(increment))) {
					s.closeWithError(errors.New("invalid stream window increment"))
					return
				}
			}
		default:
			// 不认识的帧类型直接跳过，留给以后扩展。
		}
	}
}

// lookup 返回编号为 id 的流。open 为 true 且这是服务端没见过的新编号时，把它当作客户端新打开的流。
// 已经关闭的流返回 nil，发给它的帧会被丢弃。
func (s *Session) lookup(id uint32, open bool) *stream {
	s.mu.Lock()
	if st := s.streams[id]; st != nil {
		s.mu.Unlock()
		return st
	}
	if !open || s.client || id <= s.lastPeerID || s.err != nil {
		s.mu.Unlock()
		return nil
	}
	s.lastPeerID = id
	if len(s.streams) < MaxSessionStreams {
		st := newStream(s, id)
		select {
		case s.accept <- st:
			s.streams[id] = st
			s.mu.Unlock()
			return st
		default:
		}
	}
	s.mu.Unlock()
	select {
	case s.reject <- id:
	default:
		s.closeWithError(errors.New("too many rejected streams"))
	}
	return nil
}

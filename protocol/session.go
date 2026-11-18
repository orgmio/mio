package protocol

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/orgmio/mio/internal/tlsrecord"
	"github.com/orgmio/mio/protocol/padding"
)

// acceptBacklog 是服务端已被客户端打开、但还没被 Accept 取走的流的上限，超出的流会被重置。
const acceptBacklog = 256

var (
	// ErrSessionClosed 表示会话已经关闭，不能再打开或接受流。
	ErrSessionClosed = errors.New("session closed")
	// ErrStreamReset 表示对端已放弃这条流。
	ErrStreamReset = errors.New("stream reset by peer")
)

// Session 是一条 mio 加密连接：每个帧封装为一条 TLS Application Data 记录，用 AES-256-GCM 加密，
// 5 字节记录头作为附加数据参与认证，nonce 为记录序号。一个 Session 上可以同时有多条互不阻塞的流，
// 每条流是一个 net.Conn。
//
// Session 的方法都可以并发调用。
type Session struct {
	conn   net.Conn
	reader *bufio.Reader
	client bool

	// 发送方向：writeMu 保证记录按序号依次写出。
	writeMu   sync.Mutex
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

	// openMu 让客户端新流的第一个帧按编号顺序写出：编号在持有它时分配，第一个帧在释放它之前写完。
	openMu sync.Mutex

	mu          sync.Mutex
	streams     map[uint32]*stream
	unopened    int    // 客户端已 Open、还没发过数据（因而还没有编号）的流的数量
	nextID      uint32 // 客户端下一条流的编号
	lastPeerID  uint32 // 服务端见过的最大流编号
	err         error  // 非 nil 表示会话已关闭
	idleTimeout time.Duration
	idleTimer   *time.Timer // 整个会话只有这一个空闲定时器，每次变空闲时重置

	accept chan *stream
	done   chan struct{}
}

func newSession(conn net.Conn, reader *bufio.Reader, send, recv cipher.AEAD, isClient bool) *Session {
	if reader == nil {
		reader = bufio.NewReader(conn)
	}
	return &Session{
		conn:    conn,
		reader:  reader,
		client:  isClient,
		send:    send,
		recv:    recv,
		streams: make(map[uint32]*stream),
		nextID:  1,
		accept:  make(chan *stream, acceptBacklog),
		done:    make(chan struct{}),
	}
}

// rekey 换成新的密钥并把两个方向的序号清零，只在握手阶段、start 之前调用。
func (s *Session) rekey(send, recv cipher.AEAD) {
	s.send, s.recv = send, recv
	s.sendSeq, s.recvSeq = 0, 0
}

func (s *Session) start() { go s.readLoop() }

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

// Done 返回的 channel 在会话关闭后关闭。
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
	if s.idleTimer == nil {
		s.idleTimer = time.AfterFunc(s.idleTimeout, s.idleExpired)
		return
	}
	s.idleTimer.Reset(s.idleTimeout)
}

func (s *Session) idleExpired() {
	s.mu.Lock()
	idle := s.idleTimeout > 0 && len(s.streams)+s.unopened == 0
	s.mu.Unlock()
	if idle {
		s.Close()
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
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	if !errors.Is(err, ErrSessionClosed) {
		err = fmt.Errorf("%w: %w", ErrSessionClosed, err)
	}
	s.err = err
	s.streams = make(map[uint32]*stream)
	s.mu.Unlock()

	// 等待中的流都在监听 done，关闭它即可把它们全部唤醒。
	close(s.done)
	s.conn.Close()
}

// paddingLength 算出一个帧的填充长度。
func (s *Session) paddingLength(typ byte, payloadLength int, dataFrames uint64) int {
	return framePadding(typ, payloadLength, dataFrames, MaxFramePayload-payloadLength)
}

// writeFrame 把一个帧封装成一条记录写出，padLength 超出记录容量的部分会被截掉。写失败时会话随之关闭。
// 记录在会话自己的缓冲里拼好后原地加密，不分配内存。填充为全零：它在密文里，外面看不到内容，只看得到长度。
func (s *Session) writeFrame(typ byte, id uint32, payload []byte, padLength int) error {
	if len(payload) > MaxFramePayload {
		return errors.New("frame payload too large")
	}
	padLength = max(0, min(padLength, MaxFramePayload-len(payload)))
	plainSize := FrameHeaderSize + len(payload) + padLength

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	overhead := s.send.Overhead()
	recordSize := tlsrecord.HeaderSize + plainSize + overhead
	if cap(s.writeBuf) < recordSize {
		s.writeBuf = make([]byte, tlsrecord.HeaderSize+FrameHeaderSize+MaxFramePayload+overhead)
	}
	record := s.writeBuf[:recordSize]
	header := record[:tlsrecord.HeaderSize]
	header[0], header[1], header[2] = tlsrecord.TypeAppData, 0x03, 0x03
	binary.BigEndian.PutUint16(header[3:], uint16(plainSize+overhead))
	plain := record[tlsrecord.HeaderSize : tlsrecord.HeaderSize+plainSize]
	plain[0] = typ
	binary.BigEndian.PutUint32(plain[1:5], id)
	binary.BigEndian.PutUint16(plain[5:FrameHeaderSize], uint16(len(payload)))
	copy(plain[FrameHeaderSize:], payload)
	clear(plain[FrameHeaderSize+len(payload):])
	s.send.Seal(plain[:0], seqNonce(&s.sendNonce, s.sendSeq), plain, header)
	s.sendSeq++
	if err := writeAll(s.conn, record); err != nil {
		s.closeWithError(err)
		return err
	}
	return nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// readFrame 读取并原地解密一条记录；返回的负载在下一次 readFrame 前有效。
// skipForeign 为 true 时跳过解不开的记录（握手期真站发来的记录）。
func (s *Session) readFrame(skipForeign bool) (typ byte, id uint32, payload []byte, err error) {
	var header [tlsrecord.HeaderSize]byte
	for {
		if _, err := io.ReadFull(s.reader, header[:]); err != nil {
			return 0, 0, nil, err
		}
		if !tlsrecord.ValidHeader(header[:]) {
			return 0, 0, nil, errors.New("invalid record header")
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if cap(s.readBuf) < length {
			s.readBuf = make([]byte, tlsrecord.MaxBody)
		}
		body := s.readBuf[:length]
		if _, err := io.ReadFull(s.reader, body); err != nil {
			return 0, 0, nil, err
		}
		plain, err := s.recv.Open(body[:0], seqNonce(&s.recvNonce, s.recvSeq), body, header[:])
		if err != nil {
			if skipForeign {
				continue
			}
			return 0, 0, nil, errors.New("decrypt record failed")
		}
		s.recvSeq++
		s.lastRecv.Store(time.Now().UnixNano())
		if len(plain) < FrameHeaderSize {
			return 0, 0, nil, errors.New("short frame")
		}
		payloadLength := int(binary.BigEndian.Uint16(plain[5:FrameHeaderSize]))
		if payloadLength > len(plain)-FrameHeaderSize {
			return 0, 0, nil, errors.New("invalid frame payload length")
		}
		return plain[0], binary.BigEndian.Uint32(plain[1:5]), plain[FrameHeaderSize : FrameHeaderSize+payloadLength], nil
	}
}

// waitReady 等待服务端的就绪帧并返回其服务端密钥份额，之前收到的真站记录会被丢弃。
func (s *Session) waitReady() ([]byte, error) {
	typ, _, payload, err := s.readFrame(true)
	if err != nil {
		return nil, err
	}
	if typ != FrameReady {
		return nil, errors.New("unexpected frame before ready")
	}
	return append([]byte(nil), payload...), nil
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
			if st := s.lookup(id, true); st != nil {
				if err := st.receive(payload); err != nil {
					s.closeWithError(err)
					return
				}
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
			if st := s.lookup(id, false); st != nil && len(payload) == 4 {
				st.addCredit(int(binary.BigEndian.Uint32(payload)))
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
	defer s.mu.Unlock()
	if st := s.streams[id]; st != nil {
		return st
	}
	if !open || s.client || id <= s.lastPeerID || s.err != nil {
		return nil
	}
	s.lastPeerID = id
	st := newStream(s, id)
	select {
	case s.accept <- st:
		s.streams[id] = st
		return st
	default:
		// 积压的流太多，拒绝这一条。不能在 readLoop 里等待写操作，所以另起协程发送。
		go s.writeFrame(FrameReset, id, nil, 0)
		return nil
	}
}

// stream 是会话上的一条流。
type stream struct {
	sess *Session

	writeLock sync.Mutex // 让同一条流上的 Write、CloseWrite 按调用顺序发出

	mu            sync.Mutex
	id            uint32 // 流编号；客户端的流在第一次发送数据前为 0
	buf           []byte // 已收到、还没被读走的数据
	recvWindow    int    // 对端还可以发送的字节数
	unacked       int    // 已被读走、还没通过 window 帧还给对端的字节数
	recvClosed    bool   // 对端已发来 close 帧
	reset         bool   // 对端已发来 reset 帧
	sendCredit    int    // 还可以向对端发送的字节数
	sendClosed    bool   // 已发出 close 帧，或不需要再发
	closed        bool   // 本端已调用 Close
	sentData      uint64 // 已发出的 data 帧数
	nextPadding   *padding.Range
	readDeadline  time.Time
	writeDeadline time.Time

	readNotify  chan struct{}
	writeNotify chan struct{}
}

func newStream(sess *Session, id uint32) *stream {
	return &stream{
		sess:        sess,
		id:          id,
		recvWindow:  StreamWindow,
		sendCredit:  StreamWindow,
		readNotify:  make(chan struct{}, 1),
		writeNotify: make(chan struct{}, 1),
	}
}

func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// wait 等到 ch 被通知、deadline 到期或会话关闭。
func (st *stream) wait(ch chan struct{}, deadline time.Time) error {
	select {
	case <-ch:
		return nil
	default:
	}
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-ch:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	case <-st.sess.done:
		return st.sess.closeError()
	}
}

func (st *stream) receive(payload []byte) error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	if len(payload) > st.recvWindow {
		st.mu.Unlock()
		return errors.New("peer exceeded the stream window")
	}
	st.recvWindow -= len(payload)
	st.buf = append(st.buf, payload...)
	st.mu.Unlock()
	notify(st.readNotify)
	return nil
}

func (st *stream) receiveClose() {
	st.mu.Lock()
	st.recvClosed = true
	st.mu.Unlock()
	notify(st.readNotify)
}

func (st *stream) receiveReset() {
	st.mu.Lock()
	st.reset = true
	st.mu.Unlock()
	notify(st.readNotify)
	notify(st.writeNotify)
}

func (st *stream) addCredit(increment int) {
	st.mu.Lock()
	st.sendCredit += increment
	st.mu.Unlock()
	notify(st.writeNotify)
}

// Read 读取对端发来的数据。对端半关闭后，读完剩余数据返回 io.EOF；对端放弃这条流后，读完剩余数据返回 ErrStreamReset。
func (st *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return 0, net.ErrClosed
		}
		if len(st.buf) > 0 {
			n := copy(p, st.buf)
			st.buf = st.buf[n:]
			if len(st.buf) == 0 {
				st.buf = nil
			}
			// 读走的数据攒够半个窗口再还给对端，避免每次读都发一个 window 帧。
			st.unacked += n
			id := st.id
			increment := 0
			if st.unacked >= StreamWindow/2 && !st.recvClosed && !st.reset {
				increment = st.unacked
				st.unacked = 0
				st.recvWindow += increment
			}
			st.mu.Unlock()
			if increment > 0 {
				st.sess.writeFrame(FrameWindow, id, binary.BigEndian.AppendUint32(nil, uint32(increment)), 0)
			}
			return n, nil
		}
		if st.recvClosed {
			st.mu.Unlock()
			return 0, io.EOF
		}
		if st.reset {
			st.mu.Unlock()
			return 0, ErrStreamReset
		}
		deadline := st.readDeadline
		st.mu.Unlock()
		if err := st.wait(st.readNotify, deadline); err != nil {
			return 0, err
		}
	}
}

// Write 发送数据，对端的接收窗口用完时会等待。
func (st *stream) Write(p []byte) (int, error) {
	st.writeLock.Lock()
	defer st.writeLock.Unlock()
	total := 0
	for len(p) > 0 {
		st.mu.Lock()
		if st.closed || st.sendClosed {
			st.mu.Unlock()
			return total, net.ErrClosed
		}
		if st.reset {
			st.mu.Unlock()
			return total, ErrStreamReset
		}
		n := min(len(p), st.sendCredit, MaxFramePayload)
		if n == 0 {
			deadline := st.writeDeadline
			st.mu.Unlock()
			if err := st.wait(st.writeNotify, deadline); err != nil {
				return total, err
			}
			continue
		}
		st.sendCredit -= n
		dataFrames := st.sentData
		st.sentData++
		next := st.nextPadding
		st.nextPadding = nil
		st.mu.Unlock()

		var padLength int
		if next != nil {
			padLength, _ = padding.RandomInt(next.Minimum, next.Maximum)
		} else {
			padLength = st.sess.paddingLength(FrameData, n, dataFrames)
		}
		if err := st.writeData(p[:n], padLength); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// ReadFrom 把 r 的数据发到流上，每次最多读一个帧的负载。io.Copy 会优先使用它：
// 这样大块数据正好一帧一条满记录，不会因为 io.Copy 的缓冲区比帧大而在每两条满记录后面留下一条固定长度的小记录。
func (st *stream) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, MaxFramePayload)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			written, writeErr := st.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// writeData 发出一个 data 帧。客户端的流在这里取得编号：编号的分配和第一个帧的写出都在 openMu 之内，
// 所以新流的编号在线上严格递增，服务端据此区分新流和已经关闭的旧流。
func (st *stream) writeData(payload []byte, padLength int) error {
	sess := st.sess
	st.mu.Lock()
	id := st.id
	st.mu.Unlock()
	if id != 0 {
		return sess.writeFrame(FrameData, id, payload, padLength)
	}

	sess.openMu.Lock()
	defer sess.openMu.Unlock()
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return net.ErrClosed
	}
	sess.mu.Lock()
	if sess.err != nil {
		err := sess.err
		sess.mu.Unlock()
		st.mu.Unlock()
		return err
	}
	id = sess.nextID
	sess.nextID++
	sess.unopened--
	sess.streams[id] = st
	sess.mu.Unlock()
	st.id = id
	st.mu.Unlock()
	return sess.writeFrame(FrameData, id, payload, padLength)
}

// SetNextPadding 让下一个 data 帧的填充长度在 [minimum, maximum] 内随机，只生效一次，优先于填充策略。
func (st *stream) SetNextPadding(minimum, maximum int) {
	if minimum < 0 || maximum < minimum {
		return
	}
	st.mu.Lock()
	st.nextPadding = &padding.Range{Minimum: minimum, Maximum: maximum}
	st.mu.Unlock()
}

// CloseWrite 通知对端本端不再发送数据，之后仍可继续读取。
func (st *stream) CloseWrite() error {
	st.writeLock.Lock()
	defer st.writeLock.Unlock()
	st.mu.Lock()
	if st.sendClosed || st.closed {
		st.mu.Unlock()
		return nil
	}
	st.sendClosed = true
	id, reset := st.id, st.reset
	st.mu.Unlock()
	// 没有编号的流对端并不知道，也就不需要通知。
	if reset || id == 0 {
		return nil
	}
	return st.sess.writeFrame(FrameClose, id, nil, 0)
}

// Close 关闭这条流：还没半关闭就先发 close 帧，让对端能读完已发出的数据；
// 对端还没半关闭就再发 reset 帧，告诉它不必再发。
func (st *stream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	st.buf = nil
	// 没有编号的流对端并不知道，也就不需要通知。
	id := st.id
	known := id != 0
	sendClose := known && !st.sendClosed && !st.reset
	sendReset := known && !st.recvClosed && !st.reset
	st.sendClosed = true
	st.mu.Unlock()

	notify(st.readNotify)
	notify(st.writeNotify)
	st.sess.removeStream(id)

	st.writeLock.Lock()
	defer st.writeLock.Unlock()
	if sendClose {
		st.sess.writeFrame(FrameClose, id, nil, 0)
	}
	if sendReset {
		st.sess.writeFrame(FrameReset, id, nil, 0)
	}
	return nil
}

func (st *stream) LocalAddr() net.Addr  { return st.sess.conn.LocalAddr() }
func (st *stream) RemoteAddr() net.Addr { return st.sess.conn.RemoteAddr() }

func (st *stream) SetDeadline(t time.Time) error {
	st.SetReadDeadline(t)
	return st.SetWriteDeadline(t)
}

func (st *stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.readDeadline = t
	st.mu.Unlock()
	notify(st.readNotify)
	return nil
}

func (st *stream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	st.writeDeadline = t
	st.mu.Unlock()
	notify(st.writeNotify)
	return nil
}

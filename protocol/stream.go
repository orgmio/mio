package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol/padding"
)

// ErrStreamReset 表示对端已放弃这条流。
var ErrStreamReset = errors.New("stream reset by peer")

const retainedStreamBuffer = 32 << 10

// stream 是会话上的一条流。
type stream struct {
	sess *Session

	writeLock sync.Mutex // 让同一条流上的 Write、CloseWrite 按调用顺序发出

	mu              sync.Mutex
	id              uint32       // 流编号；客户端的流在第一次发送数据前为 0
	buf             bytes.Buffer // 已收到、还没被读走的数据
	recvWindow      int          // 对端还可以发送的字节数
	unacked         int          // 已被读走、还没通过 window 帧还给对端的字节数
	recvClosed      bool         // 对端已发来 close 帧
	reset           bool         // 对端已发来 reset 帧
	sendCredit      int          // 还可以向对端发送的字节数
	sendClosed      bool         // 已发出 close 帧，或不需要再发
	closed          bool         // 本端已调用 Close
	sentData        uint64       // 已发出的 data 帧数
	nextPadding     *padding.Range
	readDeadline    time.Time
	writeDeadline   time.Time
	frameWriteLimit time.Time

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
func (st *stream) wait(ch, creditReady <-chan struct{}, deadline time.Time) error {
	select {
	case <-ch:
		return nil
	case <-creditReady:
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
	case <-creditReady:
		return nil
	case <-timeout:
		return os.ErrDeadlineExceeded
	case <-st.sess.done:
		return st.sess.closeError()
	}
}

func (st *stream) receive(payload []byte) error {
	st.mu.Lock()
	if st.closed || st.recvClosed || st.reset {
		st.mu.Unlock()
		st.sess.releaseReceiveCredit(len(payload))
		return nil
	}
	if len(payload) > st.recvWindow {
		st.mu.Unlock()
		return errors.New("peer exceeded the stream window")
	}
	st.recvWindow -= len(payload)
	st.buf.Write(payload)
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

func (st *stream) addCredit(increment int) bool {
	st.mu.Lock()
	if increment > StreamWindow-st.sendCredit {
		st.mu.Unlock()
		return false
	}
	st.sendCredit += increment
	st.mu.Unlock()
	notify(st.writeNotify)
	return true
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
		if st.buf.Len() > 0 {
			n, _ := st.buf.Read(p)
			if st.buf.Len() == 0 {
				if st.buf.Cap() > retainedStreamBuffer || st.recvClosed || st.reset {
					st.buf = bytes.Buffer{}
				} else {
					st.buf.Reset()
				}
			} else if st.buf.Cap() > max(retainedStreamBuffer, 4*st.buf.Len()) {
				st.buf = *bytes.NewBuffer(bytes.Clone(st.buf.Bytes()))
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
			st.sess.releaseReceiveCredit(n)
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
		if err := st.wait(st.readNotify, nil, deadline); err != nil {
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
		if !st.writeDeadline.IsZero() && !time.Now().Before(st.writeDeadline) {
			st.mu.Unlock()
			return total, os.ErrDeadlineExceeded
		}
		n := min(len(p), st.sendCredit, MaxFramePayload)
		var creditReady <-chan struct{}
		if n > 0 {
			n, creditReady = st.sess.takeSendCredit(n)
		}
		if n == 0 {
			deadline := st.writeDeadline
			st.mu.Unlock()
			if err := st.wait(st.writeNotify, creditReady, deadline); err != nil {
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
			st.sess.addSendCredit(n)
			st.mu.Lock()
			st.sendCredit += n
			st.sentData--
			if st.nextPadding == nil {
				st.nextPadding = next
			}
			st.mu.Unlock()
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

// takeWriteSlot waits for the shared TCP writer, observing changes to this stream's deadline.
func (st *stream) takeWriteSlot() error {
	for {
		st.mu.Lock()
		deadline := st.writeDeadline
		closed := st.closed
		st.mu.Unlock()
		if closed {
			return net.ErrClosed
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var err error
		acquired := false
		select {
		case st.sess.writeMu <- struct{}{}:
			acquired = true
		case <-st.writeNotify:
		case <-timeout:
			// Recheck the current deadline in case it changed as the timer fired.
		case <-st.sess.done:
			err = st.sess.closeError()
		}
		if timer != nil {
			timer.Stop()
		}
		if acquired || err != nil {
			return err
		}
	}
}

func (st *stream) socketWriteDeadline() time.Time {
	if !st.writeDeadline.IsZero() && st.writeDeadline.Before(st.frameWriteLimit) {
		return st.writeDeadline
	}
	return st.frameWriteLimit
}

// writeData assigns new stream IDs while holding the same slot used to send the first frame.
func (st *stream) writeData(payload []byte, padLength int) error {
	sess := st.sess
	if err := st.takeWriteSlot(); err != nil {
		return err
	}
	defer func() { <-sess.writeMu }()

	st.mu.Lock()
	if st.closed || st.reset {
		st.mu.Unlock()
		return net.ErrClosed
	}
	if !st.writeDeadline.IsZero() && !time.Now().Before(st.writeDeadline) {
		st.mu.Unlock()
		return os.ErrDeadlineExceeded
	}
	st.frameWriteLimit = time.Now().Add(sessionWriteTimeout)
	if err := sess.conn.SetWriteDeadline(st.socketWriteDeadline()); err != nil {
		st.frameWriteLimit = time.Time{}
		st.mu.Unlock()
		return err
	}
	defer func() {
		st.mu.Lock()
		st.frameWriteLimit = time.Time{}
		st.mu.Unlock()
	}()

	sess.mu.Lock()
	if sess.err != nil {
		err := sess.err
		sess.mu.Unlock()
		st.mu.Unlock()
		return err
	}
	if st.id == 0 {
		st.id = sess.nextID
		sess.nextID++
		sess.unopened--
		sess.streams[st.id] = st
	}
	sess.mu.Unlock()
	id := st.id
	st.mu.Unlock()
	return sess.writeFrameLocked(FrameData, id, payload, padLength)
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
	discarded := st.buf.Len()
	st.buf = bytes.Buffer{}
	// 没有编号的流对端并不知道，也就不需要通知。
	id := st.id
	known := id != 0
	sendClose := known && !st.sendClosed && !st.reset
	sendReset := known && !st.recvClosed && !st.reset
	st.sendClosed = true
	st.mu.Unlock()
	st.sess.releaseReceiveCredit(discarded)

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
	var err error
	if !st.frameWriteLimit.IsZero() {
		err = st.sess.conn.SetWriteDeadline(st.socketWriteDeadline())
	}
	st.mu.Unlock()
	notify(st.writeNotify)
	return err
}

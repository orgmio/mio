package protocol

import (
	"encoding/binary"
	"time"
)

// SessionWindow 是会话在每个方向上为所有流分配的初始数据帧总额度，以字节计。
const SessionWindow = 32 << 20

func (s *Session) takeSendCredit(limit int) (int, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(limit, s.sendCredit)
	s.sendCredit -= n
	return n, s.creditReady
}

func (s *Session) addSendCredit(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > SessionWindow-s.sendCredit {
		return false
	}
	if s.sendCredit == 0 {
		close(s.creditReady)
		s.creditReady = make(chan struct{})
	}
	s.sendCredit += n
	return true
}

func (s *Session) takeReceiveCredit(n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > s.recvCredit {
		return false
	}
	s.recvCredit -= n
	return true
}

func (s *Session) releaseReceiveCredit(n int) {
	if n == 0 {
		return
	}
	s.mu.Lock()
	s.recvConsumed += n
	s.mu.Unlock()
	notify(s.windowReady)
}

// 读取方无需等待共享连接上的写入操作。窗口更新会在短暂等待后批量发送，
// 包括会话额度耗尽后少量读取所释放的额度。
func (s *Session) writeControlFrames() {
	for {
		var err error
		select {
		case <-s.done:
			return
		case id := <-s.reject:
			err = s.writeFrame(FrameReset, id, nil, 0)
		case <-s.windowReady:
			timer := time.NewTimer(5 * time.Millisecond)
			select {
			case <-s.done:
				timer.Stop()
				return
			case <-timer.C:
			}
			s.mu.Lock()
			n := s.recvConsumed
			s.recvConsumed = 0
			s.recvCredit += n
			s.mu.Unlock()
			if n > 0 {
				err = s.writeFrame(FrameWindow, 0, binary.BigEndian.AppendUint32(nil, uint32(n)), 0)
			}
		}
		if err != nil {
			s.closeWithError(err)
			return
		}
	}
}

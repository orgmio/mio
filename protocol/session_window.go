package protocol

import (
	"encoding/binary"
	"time"
)

// SessionWindow is the initial aggregate DATA credit in each direction.
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

// The reader never waits for the shared socket writer. Batch window updates
// briefly, including small reads that free the only available session credit.
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

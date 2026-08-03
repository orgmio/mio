package quic

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/wire"
)

const disableClientHelloScramblingEnv = "QUIC_GO_DISABLE_CLIENTHELLO_SCRAMBLING"

// The baseCryptoStream is used by the cryptoStream and the initialCryptoStream.
// This allows us to implement different logic for PopCryptoFrame for the two streams.
type baseCryptoStream struct {
	queue frameSorter

	highestOffset protocol.ByteCount
	finished      bool

	writeOffset protocol.ByteCount
	writeBuf    []byte
}

func newCryptoStream() *cryptoStream {
	return &cryptoStream{baseCryptoStream{queue: *newFrameSorter()}}
}

func (s *baseCryptoStream) HandleCryptoFrame(f *wire.CryptoFrame) error {
	highestOffset := f.Offset + protocol.ByteCount(len(f.Data))
	if maxOffset := highestOffset; maxOffset > protocol.MaxCryptoStreamOffset {
		return &qerr.TransportError{
			ErrorCode:    qerr.CryptoBufferExceeded,
			ErrorMessage: fmt.Sprintf("received invalid offset %d on crypto stream, maximum allowed %d", maxOffset, protocol.MaxCryptoStreamOffset),
		}
	}
	if s.finished {
		if highestOffset > s.highestOffset {
			// reject crypto data received after this stream was already finished
			return &qerr.TransportError{
				ErrorCode:    qerr.ProtocolViolation,
				ErrorMessage: "received crypto data after change of encryption level",
			}
		}
		// ignore data with a smaller offset than the highest received
		// could e.g. be a retransmission
		return nil
	}
	s.highestOffset = max(s.highestOffset, highestOffset)
	return s.queue.Push(f.Data, f.Offset, nil)
}

// GetCryptoData retrieves data that was received in CRYPTO frames
func (s *baseCryptoStream) GetCryptoData() []byte {
	_, data, _ := s.queue.Pop()
	return data
}

func (s *baseCryptoStream) Finish() error {
	if s.queue.HasMoreData() {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "encryption level changed, but crypto stream has more data to read",
		}
	}
	s.finished = true
	return nil
}

// Writes writes data that should be sent out in CRYPTO frames
func (s *baseCryptoStream) Write(p []byte) (int, error) {
	s.writeBuf = append(s.writeBuf, p...)
	return len(p), nil
}

func (s *baseCryptoStream) HasData() bool {
	return len(s.writeBuf) > 0
}

func (s *baseCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	f := &wire.CryptoFrame{Offset: s.writeOffset}
	n := min(f.MaxDataLen(maxLen), protocol.ByteCount(len(s.writeBuf)))
	if n <= 0 {
		return nil
	}
	f.Data = s.writeBuf[:n]
	s.writeBuf = s.writeBuf[n:]
	s.writeOffset += n
	return f
}

type cryptoStream struct {
	baseCryptoStream
}

type clientHelloCut struct {
	start protocol.ByteCount
	end   protocol.ByteCount
}

type initialCryptoStream struct {
	baseCryptoStream

	scramble          bool
	braveLayout       bool
	braveSegmentIndex int
	bravePause        bool
	end               protocol.ByteCount
	cuts              [2]clientHelloCut
}

var braveClientHelloSegments = [...]clientHelloCut{
	{start: 18, end: 61}, {start: 66, end: 69}, {start: 0, end: 18}, {start: 62, end: 63},
	{start: 965, end: 1787}, {start: 65, end: 66}, {start: 63, end: 65}, {start: 61, end: 62},
	{start: 921, end: 965}, {start: 452, end: 858}, {start: 449, end: 452}, {start: 69, end: 424},
	{start: 426, end: 430}, {start: 424, end: 426}, {start: 907, end: 921}, {start: 430, end: 432},
	{start: 858, end: 907}, {start: 432, end: 449},
}

func newInitialCryptoStream(isClient bool) *initialCryptoStream {
	var scramble bool
	if isClient {
		disabled, err := strconv.ParseBool(os.Getenv(disableClientHelloScramblingEnv))
		scramble = err != nil || !disabled
	}
	s := &initialCryptoStream{
		baseCryptoStream: baseCryptoStream{queue: *newFrameSorter()},
		scramble:         scramble,
	}
	for i := range len(s.cuts) {
		s.cuts[i].start = protocol.InvalidByteCount
		s.cuts[i].end = protocol.InvalidByteCount
	}
	return s
}

func (s *initialCryptoStream) HasData() bool {
	// The ClientHello might be written in multiple parts.
	// In order to correctly split the ClientHello, we need the entire ClientHello has been queued.
	if s.scramble && s.writeOffset == 0 && s.end == 0 {
		return false
	}
	return s.baseCryptoStream.HasData()
}

func (s *initialCryptoStream) Write(p []byte) (int, error) {
	s.writeBuf = append(s.writeBuf, p...)
	if !s.scramble {
		return len(p), nil
	}
	if s.cuts[0].start == protocol.InvalidByteCount {
		sniPos, sniLen, echPos, err := findSNIAndECH(s.writeBuf)
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return len(p), nil
		}
		if err != nil {
			return len(p), err
		}
		if sniPos == -1 && echPos == -1 {
			// Neither SNI nor ECH found.
			// There's nothing to scramble.
			s.scramble = false
			return len(p), nil
		}
		s.end = protocol.ByteCount(len(s.writeBuf))
		if s.braveLayout && s.end == 1787 {
			return len(p), nil
		}
		s.cuts[0].start = protocol.ByteCount(sniPos + sniLen/2) // right in the middle
		s.cuts[0].end = protocol.ByteCount(sniPos + sniLen)
		if echPos > 0 {
			// ECH extension found, cut the ECH extension type value (a uint16) in half
			start := protocol.ByteCount(echPos + 1)
			s.cuts[1].start = start
			// cut somewhere (16 bytes), most likely in the ECH extension value
			s.cuts[1].end = min(start+16, s.end)
		}
		slices.SortFunc(s.cuts[:], func(a, b clientHelloCut) int {
			if a.start == protocol.InvalidByteCount {
				return 1
			}
			if a.start > b.start {
				return 1
			}
			return -1
		})
	}
	return len(p), nil
}

func (s *initialCryptoStream) PopCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	if !s.scramble {
		return s.baseCryptoStream.PopCryptoFrame(maxLen)
	}
	if s.braveLayout && s.end == 1787 {
		return s.popBraveCryptoFrame(maxLen)
	}

	// send out the skipped parts
	if s.writeOffset == s.end {
		var foundCuts bool
		var f *wire.CryptoFrame
		for i, c := range s.cuts {
			if c.start == protocol.InvalidByteCount {
				continue
			}
			foundCuts = true
			if f != nil {
				break
			}
			f = &wire.CryptoFrame{Offset: c.start}
			n := min(f.MaxDataLen(maxLen), c.end-c.start)
			if n <= 0 {
				return nil
			}
			f.Data = s.writeBuf[c.start : c.start+n]
			s.cuts[i].start += n
			if s.cuts[i].start == c.end {
				s.cuts[i].start = protocol.InvalidByteCount
				s.cuts[i].end = protocol.InvalidByteCount
				foundCuts = false
			}
		}
		if !foundCuts {
			// no more cuts found, we're done sending out everything up until s.end
			s.writeBuf = s.writeBuf[s.end:]
			s.end = protocol.InvalidByteCount
			s.scramble = false
		}
		return f
	}

	nextCut := clientHelloCut{start: protocol.InvalidByteCount, end: protocol.InvalidByteCount}
	for _, c := range s.cuts {
		if c.start == protocol.InvalidByteCount {
			continue
		}
		if c.start > s.writeOffset {
			nextCut = c
			break
		}
	}
	f := &wire.CryptoFrame{Offset: s.writeOffset}
	maxOffset := nextCut.start
	if maxOffset == protocol.InvalidByteCount {
		maxOffset = s.end
	}
	n := min(f.MaxDataLen(maxLen), maxOffset-s.writeOffset)
	if n <= 0 {
		return nil
	}
	f.Data = s.writeBuf[s.writeOffset : s.writeOffset+n]
	// Don't reslice the writeBuf yet.
	// This is done once all parts have been sent out.
	s.writeOffset += n
	if s.writeOffset == nextCut.start {
		s.writeOffset = nextCut.end
	}

	return f
}

func (s *initialCryptoStream) popBraveCryptoFrame(maxLen protocol.ByteCount) *wire.CryptoFrame {
	if s.bravePause {
		s.bravePause = false
		return nil
	}
	if s.braveSegmentIndex >= len(braveClientHelloSegments) {
		return nil
	}
	segment := braveClientHelloSegments[s.braveSegmentIndex]
	f := &wire.CryptoFrame{Offset: segment.start, Data: s.writeBuf[segment.start:segment.end]}
	if f.Length(protocol.Version1) > maxLen {
		return nil
	}
	s.braveSegmentIndex++
	if s.braveSegmentIndex == 8 {
		s.bravePause = true
	}
	if s.braveSegmentIndex == len(braveClientHelloSegments) {
		s.writeBuf = s.writeBuf[s.end:]
		s.writeOffset = s.end
		s.scramble = false
	}
	return f
}

func (s *initialCryptoStream) bravePrefixFrames() []wire.Frame {
	if !s.braveLayout || s.end != 1787 {
		return nil
	}
	switch s.braveSegmentIndex {
	case 0:
		return []wire.Frame{wire.PaddingFrame(6)}
	case 8:
		return []wire.Frame{wire.PaddingFrame(2), &wire.PingFrame{}}
	default:
		return nil
	}
}

func (s *initialCryptoStream) braveSuffixFrames() []wire.Frame {
	if !s.braveLayout || s.end != 1787 {
		return nil
	}
	switch s.braveSegmentIndex {
	case 4:
		return []wire.Frame{&wire.PingFrame{}}
	case 5:
		return []wire.Frame{wire.PaddingFrame(5), &wire.PingFrame{}}
	case 6:
		return []wire.Frame{wire.PaddingFrame(8)}
	case 8:
		return []wire.Frame{wire.PaddingFrame(99), &wire.PingFrame{}, &wire.PingFrame{}}
	case 10:
		return []wire.Frame{wire.PaddingFrame(11)}
	case 11:
		return []wire.Frame{wire.PaddingFrame(1)}
	case 14:
		return []wire.Frame{wire.PaddingFrame(75)}
	case 15:
		return []wire.Frame{&wire.PingFrame{}}
	case 17:
		return []wire.Frame{wire.PaddingFrame(26)}
	default:
		return nil
	}
}

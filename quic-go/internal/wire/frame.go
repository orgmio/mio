package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
)

// A Frame in QUIC
type Frame interface {
	Append(b []byte, version protocol.Version) ([]byte, error)
	Length(version protocol.Version) protocol.ByteCount
}

// PaddingFrame writes a run of PADDING bytes. It is used by the Chromium
// ClientHello layout, where padding is deliberately interspersed with CRYPTO
// and PING frames instead of being emitted only at the end of the packet.
type PaddingFrame protocol.ByteCount

func (f PaddingFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	return append(b, make([]byte, int(f))...), nil
}

func (f PaddingFrame) Length(_ protocol.Version) protocol.ByteCount { return protocol.ByteCount(f) }

// IsProbingFrame returns true if the frame is a probing frame.
// See section 9.1 of RFC 9000.
func IsProbingFrame(f Frame) bool {
	switch f.(type) {
	case *PathChallengeFrame, *PathResponseFrame, *NewConnectionIDFrame:
		return true
	}
	return false
}

// IsProbingFrameType returns true if the FrameType is a probing frame.
// See section 9.1 of RFC 9000.
func IsProbingFrameType(f FrameType) bool {
	//nolint:exhaustive // PATH_CHALLENGE, PATH_RESPONSE and NEW_CONNECTION_ID are the only probing frames
	switch f {
	case FrameTypePathChallenge, FrameTypePathResponse, FrameTypeNewConnectionID:
		return true
	default:
		return false
	}
}

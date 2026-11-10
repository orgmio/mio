package padding

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

const (
	RecordHeaderSize = 5
	FrameHeaderSize  = 3
	MaxRecordBody    = 16384 + 256
)

type Range struct {
	Minimum int
	Maximum int
}

func RandomInt(minimum, maximum int) (int, error) {
	if minimum < 0 || maximum < minimum {
		return 0, errors.New("invalid random range")
	}
	span := big.NewInt(int64(maximum - minimum + 1))
	value, err := rand.Int(rand.Reader, span)
	if err != nil {
		return 0, err
	}
	return minimum + int(value.Int64()), nil
}

func RandomBytes(length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("negative padding length")
	}
	padding := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		return nil, err
	}
	return padding, nil
}

func RandomPadding(minimum, maximum, maxPadding int) ([]byte, error) {
	if maxPadding < 0 {
		return nil, errors.New("negative maximum padding")
	}
	minimum = min(minimum, maxPadding)
	maximum = min(maximum, maxPadding)
	if maximum < minimum {
		maximum = minimum
	}
	length, err := RandomInt(minimum, maximum)
	if err != nil {
		return nil, err
	}
	return RandomBytes(length)
}

func FramePadding(payloadLength int, dataFrame uint64, ready, data bool, maxPadding int) ([]byte, error) {
	if maxPadding < 0 {
		return nil, errors.New("negative maximum padding")
	}
	minimum, maximum := 0, 0
	switch {
	case ready:
		maximum = min(1024, maxPadding)
	case data && dataFrame < 8 && payloadLength < 900:
		minimum = max(0, 900-FrameHeaderSize-payloadLength)
		maximum = max(minimum, 1400-FrameHeaderSize-payloadLength)
		minimum = min(minimum, maxPadding)
		maximum = min(maximum, maxPadding)
	case data && dataFrame < 8:
		maximum = min(255, maxPadding)
	default:
		return nil, nil
	}
	length, err := RandomInt(minimum, maximum)
	if err != nil {
		return nil, err
	}
	return RandomBytes(length)
}

func RecordLength(header []byte) (int, bool) {
	if len(header) < RecordHeaderSize || header[0] < 0x14 || header[0] > 0x17 ||
		header[1] != 0x03 || header[2] < 0x01 || header[2] > 0x04 {
		return 0, false
	}
	length := int(binary.BigEndian.Uint16(header[3:RecordHeaderSize]))
	if length > MaxRecordBody {
		return 0, false
	}
	return RecordHeaderSize + length, true
}

func IsPossibleRecordPrefix(prefix []byte) bool {
	if len(prefix) == 0 || len(prefix) >= RecordHeaderSize {
		return false
	}
	if prefix[0] < 0x14 || prefix[0] > 0x17 {
		return false
	}
	if len(prefix) >= 2 && prefix[1] != 0x03 {
		return false
	}
	if len(prefix) >= 3 && (prefix[2] < 0x01 || prefix[2] > 0x04) {
		return false
	}
	return true
}

func IsHandshakeStart(record []byte) bool {
	total, ok := RecordLength(record)
	return ok && total == len(record) && record[0] == 0x16 && total > RecordHeaderSize &&
		(record[RecordHeaderSize] == 0x01 || record[RecordHeaderSize] == 0x02)
}

func HasHandshakeStart(header, payload []byte) bool {
	if _, ok := RecordLength(header); !ok || len(header) < RecordHeaderSize || header[0] != 0x16 || len(payload) == 0 {
		return false
	}
	return payload[0] == 0x01 || payload[0] == 0x02
}

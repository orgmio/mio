package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// MaxDatagramSize includes the encoded address, leaving room for the three
// reserved and fragment bytes in an IPv4 SOCKS5 UDP packet.
const MaxDatagramSize = 65504

const minDatagramSize = 5 // Address type, name length, one-byte name, and port.

var errDatagramSize = errors.New("invalid mio UDP datagram size")

// WriteDatagram writes one address and its UDP payload, prefixed by their total length.
func WriteDatagram(w io.Writer, datagram []byte) error {
	if len(datagram) < minDatagramSize || len(datagram) > MaxDatagramSize {
		return errDatagramSize
	}
	record := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(datagram)), uint16(len(datagram)))
	return writeAll(w, append(record, datagram...))
}

// ReadDatagram reads one address and its UDP payload into a caller-owned buffer.
func ReadDatagram(r io.Reader, buf []byte) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < minDatagramSize || size > MaxDatagramSize || size > len(buf) {
		return nil, errDatagramSize
	}
	if _, err := io.ReadFull(r, buf[:size]); err != nil {
		return nil, err
	}
	return buf[:size], nil
}

// ParseDatagram splits a datagram into its encoded endpoint and its original UDP payload.
func ParseDatagram(datagram []byte) (endpoint string, payload []byte, err error) {
	r := bytes.NewReader(datagram)
	endpoint, err = ReadRequest(r)
	if err != nil {
		return "", nil, err
	}
	return endpoint, datagram[len(datagram)-r.Len():], nil
}

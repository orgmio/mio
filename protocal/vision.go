package protocal

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	visionBudget     = 16 * 1024
	visionMaxChunk   = 65535
	visionMaxPadding = 768
	visionDataFrame  = 1
	visionRawFrame   = 0
)

// visionConn obscures early inner write boundaries with bounded random padding.
// Each direction independently switches to unframed writes after a small prefix.
type visionConn struct {
	net.Conn
	readMu        sync.Mutex
	writeMu       sync.Mutex
	readRaw       bool
	writeRaw      bool
	written       int
	readRemainder []byte
}

func newVisionConn(conn net.Conn) net.Conn { return &visionConn{Conn: conn} }

func (c *visionConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.writeRaw {
		return c.Conn.Write(p)
	}
	if c.written >= visionBudget {
		packet := append([]byte{visionRawFrame, 0, 0, 0, 0}, p...)
		if err := writeAll(c.Conn, packet); err != nil {
			return 0, err
		}
		c.writeRaw = true
		return len(p), nil
	}
	chunkSize := min(len(p), visionMaxChunk)
	paddingSize, err := randomBetween(0, visionMaxPadding)
	if err != nil {
		return 0, err
	}
	frame := make([]byte, 5+chunkSize+paddingSize)
	frame[0] = visionDataFrame
	binary.BigEndian.PutUint16(frame[1:3], uint16(chunkSize))
	binary.BigEndian.PutUint16(frame[3:5], uint16(paddingSize))
	copy(frame[5:], p[:chunkSize])
	if paddingSize > 0 {
		if _, err := rand.Read(frame[5+chunkSize:]); err != nil {
			return 0, err
		}
	}
	if err := writeAll(c.Conn, frame); err != nil {
		return 0, err
	}
	c.written += chunkSize
	return chunkSize, nil
}

func (c *visionConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(c.readRemainder) > 0 {
		n := copy(p, c.readRemainder)
		c.readRemainder = c.readRemainder[n:]
		return n, nil
	}
	if c.readRaw {
		return c.Conn.Read(p)
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return 0, err
	}
	if header[0] == visionRawFrame {
		c.readRaw = true
		return c.Conn.Read(p)
	}
	if header[0] != visionDataFrame {
		return 0, fmt.Errorf("invalid vision frame type %d", header[0])
	}
	dataSize := int(binary.BigEndian.Uint16(header[1:3]))
	paddingSize := int(binary.BigEndian.Uint16(header[3:5]))
	if dataSize < 1 || dataSize > visionMaxChunk || paddingSize > visionMaxPadding {
		return 0, fmt.Errorf("invalid vision frame sizes %d/%d", dataSize, paddingSize)
	}
	frame := make([]byte, dataSize+paddingSize)
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}
	n := copy(p, frame[:dataSize])
	if n < dataSize {
		c.readRemainder = append(c.readRemainder[:0], frame[n:dataSize]...)
	}
	return n, nil
}

func randomBetween(low, high int) (int, error) {
	if high <= low {
		return low, nil
	}
	var value [2]byte
	if _, err := rand.Read(value[:]); err != nil {
		return 0, err
	}
	return low + int(binary.BigEndian.Uint16(value[:]))%(high-low+1), nil
}

func writeAll(w io.Writer, p []byte) error {
	_, err := io.Copy(w, bytesReader(p))
	return err
}

type sliceReader []byte

func bytesReader(p []byte) *sliceReader { r := sliceReader(p); return &r }
func (r *sliceReader) Read(p []byte) (int, error) {
	if len(*r) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *r)
	*r = (*r)[n:]
	return n, nil
}

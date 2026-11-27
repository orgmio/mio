package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// MaxDatagramSize 包含编码后的地址，并为 IPv4 SOCKS5 UDP 数据报的
// 保留字段和分片字段留出 3 个字节。
const MaxDatagramSize = 65504

const minDatagramSize = 5 // 地址类型、域名长度、1 字节域名和端口。

var errDatagramSize = errors.New("invalid mio UDP datagram size")

var datagramBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2+MaxDatagramSize)
		return &b
	},
}

// WriteDatagram 先写入总长度，再写入地址及其 UDP 负载。
func WriteDatagram(w io.Writer, datagram []byte) error {
	if len(datagram) < minDatagramSize || len(datagram) > MaxDatagramSize {
		return errDatagramSize
	}
	bp := datagramBufPool.Get().(*[]byte)
	buf := (*bp)[:2+len(datagram)]
	binary.BigEndian.PutUint16(buf[:2], uint16(len(datagram)))
	copy(buf[2:], datagram)
	err := writeAll(w, buf)
	datagramBufPool.Put(bp)
	return err
}

// ReadDatagram 将地址及其 UDP 负载读入调用方提供的缓冲区。
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

// ParseDatagram 从数据报中解析出端点，并返回原始 UDP 负载。
func ParseDatagram(datagram []byte) (endpoint string, payload []byte, err error) {
	r := bytes.NewReader(datagram)
	endpoint, err = ReadRequest(r)
	if err != nil {
		return "", nil, err
	}
	return endpoint, datagram[len(datagram)-r.Len():], nil
}

package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	recordHandshake  = 0x16
	recordAppData    = 0x17
	recordHeaderSize = 5
	maxRecordBody    = 16384 + 256

	handshakeServerHello = 0x02
)

var errAuthenticated = errors.New("authenticated")

// bufferedConn 把认证记录之后已读入缓冲的数据还给上层。
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func validRecordHeader(header []byte, length int) bool {
	return header[0] >= 0x14 && header[0] <= recordAppData &&
		header[1] == 0x03 && header[2] >= 0x01 && header[2] <= 0x04 &&
		length <= maxRecordBody
}

// copyRecords 按 TLS 记录从 src 转发到 dst；inspect 返回 true 时吞掉该记录并以 errAuthenticated 结束。
// 一旦数据不像 TLS，就停止解析并原样转发剩余内容。
func copyRecords(dst io.Writer, src *bufio.Reader, inspect func(header, body []byte) bool) error {
	header := make([]byte, recordHeaderSize)
	for {
		if _, err := io.ReadFull(src, header); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if !validRecordHeader(header, length) {
			if _, err := dst.Write(header); err != nil {
				return err
			}
			_, err := io.Copy(dst, src)
			return err
		}

		record := make([]byte, recordHeaderSize+length)
		copy(record, header)
		n, err := io.ReadFull(src, record[recordHeaderSize:])
		if err != nil {
			dst.Write(record[:recordHeaderSize+n])
			return err
		}
		if inspect(header, record[recordHeaderSize:]) {
			return errAuthenticated
		}
		if _, err := dst.Write(record); err != nil {
			return err
		}
	}
}

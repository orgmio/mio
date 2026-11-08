package protocol

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

const (
	RecordHandshake  = 0x16
	RecordAppData    = 0x17
	RecordHeaderSize = 5
	maxRecordBody    = 16384 + 256

	HandshakeClientHello = 0x01
	HandshakeServerHello = 0x02
)

var ErrAuthenticated = errors.New("authenticated")

func ValidRecordHeader(header []byte, length int) bool {
	return header[0] >= 0x14 && header[0] <= RecordAppData &&
		header[1] == 0x03 && header[2] >= 0x01 && header[2] <= 0x04 &&
		length <= maxRecordBody
}

// CopyRecords 按 TLS 记录从 src 转发到 dst；inspect 返回 true 时吞掉该记录并以 ErrAuthenticated 结束。
// 一旦数据不像 TLS，就停止解析并原样转发剩余内容。
func CopyRecords(dst io.Writer, src *bufio.Reader, inspect func(header, body []byte) bool) error {
	header := make([]byte, RecordHeaderSize)
	for {
		if _, err := io.ReadFull(src, header); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if !ValidRecordHeader(header, length) {
			if _, err := dst.Write(header); err != nil {
				return err
			}
			_, err := io.Copy(dst, src)
			return err
		}

		record := make([]byte, RecordHeaderSize+length)
		copy(record, header)
		n, err := io.ReadFull(src, record[RecordHeaderSize:])
		if err != nil {
			dst.Write(record[:RecordHeaderSize+n])
			return err
		}
		if inspect(header, record[RecordHeaderSize:]) {
			return ErrAuthenticated
		}
		if _, err := dst.Write(record); err != nil {
			return err
		}
	}
}

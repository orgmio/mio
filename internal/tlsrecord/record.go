// Package tlsrecord 解析与转发 TLS 记录，供 mio 的伪装转发和帧层共用。
package tlsrecord

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

const (
	TypeHandshake = 0x16
	TypeAppData   = 0x17

	HeaderSize = 5
	MaxBody    = 16384 + 256

	HandshakeClientHello = 0x01
	HandshakeServerHello = 0x02
)

// ErrAuthenticated 表示 CopyRecords 的 inspect 认出了认证记录并停止转发。
var ErrAuthenticated = errors.New("authenticated")

// ValidHeader 判断 5 字节记录头是否像一条 TLS 记录。
func ValidHeader(header []byte) bool {
	if len(header) < HeaderSize {
		return false
	}
	return header[0] >= 0x14 && header[0] <= TypeAppData &&
		header[1] == 0x03 && header[2] >= 0x01 && header[2] <= 0x04 &&
		int(binary.BigEndian.Uint16(header[3:HeaderSize])) <= MaxBody
}

// Length 返回以 data 开头的 TLS 记录总长度（含记录头）；不像 TLS 记录时 ok 为 false。
func Length(data []byte) (total int, ok bool) {
	if !ValidHeader(data) {
		return 0, false
	}
	return HeaderSize + int(binary.BigEndian.Uint16(data[3:HeaderSize])), true
}

// IsPossiblePrefix 判断不足 5 字节的 prefix 是否可能是某条 TLS 记录头的开头。
func IsPossiblePrefix(prefix []byte) bool {
	if len(prefix) == 0 || len(prefix) >= HeaderSize {
		return false
	}
	if prefix[0] < 0x14 || prefix[0] > TypeAppData {
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

// CopyRecords 按 TLS 记录从 src 转发到 dst；inspect 返回 true 时吞掉该记录并以 ErrAuthenticated 结束。
// 一旦数据不像 TLS，就停止解析并原样转发剩余内容。
func CopyRecords(dst io.Writer, src *bufio.Reader, inspect func(header, body []byte) bool) error {
	header := make([]byte, HeaderSize)
	for {
		if _, err := io.ReadFull(src, header); err != nil {
			return err
		}
		if !ValidHeader(header) {
			if _, err := dst.Write(header); err != nil {
				return err
			}
			_, err := io.Copy(dst, src)
			return err
		}
		length := int(binary.BigEndian.Uint16(header[3:]))

		record := make([]byte, HeaderSize+length)
		copy(record, header)
		n, err := io.ReadFull(src, record[HeaderSize:])
		if err != nil {
			dst.Write(record[:HeaderSize+n])
			return err
		}
		if inspect(header, record[HeaderSize:]) {
			return ErrAuthenticated
		}
		if _, err := dst.Write(record); err != nil {
			return err
		}
	}
}

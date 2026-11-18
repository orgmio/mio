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

// Action 是 CopyRecords 的 inspect 对一条记录的处置。
type Action int

const (
	Forward     Action = iota // 转发这条记录，继续检查后面的记录
	Claim                     // 吞掉这条记录，以 ErrAuthenticated 结束
	Passthrough               // 转发这条记录，之后不再解析，原样转发剩余内容
)

// ValidHeader 判断 5 字节记录头是否像一条 TLS 记录。
func ValidHeader(header []byte) bool {
	if len(header) < HeaderSize {
		return false
	}
	return header[0] >= 0x14 && header[0] <= TypeAppData &&
		header[1] == 0x03 && header[2] >= 0x01 && header[2] <= 0x04 &&
		int(binary.BigEndian.Uint16(header[3:HeaderSize])) <= MaxBody
}

// CleanEOF 判断 CopyRecords 的返回值是否表示 src 正常结束（对端发了 FIN），而不是读写出错。
func CleanEOF(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// CopyRecords 按 TLS 记录从 src 转发到 dst，每条记录交给 inspect 决定如何处置。
// 一旦数据不像 TLS，就停止解析并原样转发剩余内容。src 正常结束时，已读到的不完整记录也会照样转发。
func CopyRecords(dst io.Writer, src *bufio.Reader, inspect func(header, body []byte) Action) error {
	header := make([]byte, HeaderSize)
	for {
		if n, err := io.ReadFull(src, header); err != nil {
			// 只有 src 正常结束时才转发残缺的部分；本端主动关闭 src 时（例如认证成功后）残缺记录必须丢掉，
			// 否则对端会被半条记录带偏，后面的记录全部错位。
			if n > 0 && CleanEOF(err) {
				dst.Write(header[:n])
			}
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
			if CleanEOF(err) {
				dst.Write(record[:HeaderSize+n])
			}
			return err
		}
		action := inspect(header, record[HeaderSize:])
		if action == Claim {
			return ErrAuthenticated
		}
		if _, err := dst.Write(record); err != nil {
			return err
		}
		if action == Passthrough {
			_, err := io.Copy(dst, src)
			return err
		}
	}
}

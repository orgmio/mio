package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	addrIPv4   = 1
	addrDomain = 3
	addrIPv6   = 4

	replyOK   byte = 0
	replyFail byte = 1
)

// WriteRequest 发送目标地址，格式为 [类型][地址][端口]，在加密连接上一次写出。
func WriteRequest(w io.Writer, target string) error {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q", portText)
	}

	var buf []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append([]byte{addrIPv4}, ip4...)
		} else {
			buf = append([]byte{addrIPv6}, ip...)
		}
	} else {
		if host == "" || len(host) > 255 {
			return fmt.Errorf("invalid host %q", host)
		}
		buf = append([]byte{addrDomain, byte(len(host))}, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	_, err = w.Write(buf)
	return err
}

// ReadRequest 读取客户端发来的目标地址，返回 host:port。
func ReadRequest(r io.Reader) (string, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return "", err
	}

	var host string
	switch kind[0] {
	case addrIPv4, addrIPv6:
		ip := make([]byte, 4)
		if kind[0] == addrIPv6 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case addrDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", err
		}
		if length[0] == 0 {
			return "", errors.New("empty domain")
		}
		name := make([]byte, length[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", fmt.Errorf("unknown address type %d", kind[0])
	}

	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

// WriteReply 告知客户端目标是否连接成功。
func WriteReply(w io.Writer, ok bool) error {
	status := replyFail
	if ok {
		status = replyOK
	}
	_, err := w.Write([]byte{status})
	return err
}

var ErrConnectFailed = errors.New("server failed to connect target")

func ReadReply(r io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return err
	}
	if status[0] != replyOK {
		return ErrConnectFailed
	}
	return nil
}

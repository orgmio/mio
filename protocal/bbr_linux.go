//go:build linux

package protocal

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func enableTCPBBR(raw syscall.RawConn) error {
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
	}); err != nil {
		return err
	}
	return socketErr
}

func preferTCPBBR(conn net.Conn) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := syscallConn.SyscallConn()
	if err == nil {
		_ = enableTCPBBR(raw)
	}
}

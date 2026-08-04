//go:build !linux

package protocal

import "net"

func preferTCPBBR(net.Conn) {}

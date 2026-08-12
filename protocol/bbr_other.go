//go:build !linux

package mio

import "net"

func preferTCPBBR(net.Conn) {}

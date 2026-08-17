//go:build !linux

package mio

import "net"

func preferTCPBBR(conn net.Conn) { raiseTCPBuffers(conn) }

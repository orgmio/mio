package server

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"sync/atomic"

	"github.com/orgmio/mio/protocol"
)

// relay 在客户端与真站之间转发 TLS 记录，直到客户端发来合法的认证记录，之后返回加密连接。
func (s *Server) relay(client, dest net.Conn) (net.Conn, bool) {
	clientReader := bufio.NewReader(client)
	var serverRandom atomic.Pointer[[]byte]
	var clientRandom []byte // 仅在客户端方向的转发协程中读写
	var share []byte
	var connectionClaimed atomic.Bool

	camouflageStopped := make(chan struct{})
	go func() {
		defer close(camouflageStopped)
		protocol.CopyRecords(client, bufio.NewReader(dest), func(header, body []byte) bool {
			// 遇到 HelloRetryRequest 时会有两条 ServerHello，以最后一条为准。
			if header[0] == protocol.RecordHandshake && len(body) >= 38 && body[0] == protocol.HandshakeServerHello {
				random := bytes.Clone(body[6:38])
				serverRandom.Store(&random)
			}
			return false
		})
		if !connectionClaimed.Load() {
			client.Close()
		}
	}()

	err := protocol.CopyRecords(dest, clientReader, func(header, body []byte) bool {
		if header[0] == protocol.RecordHandshake && len(body) >= 38 && body[0] == protocol.HandshakeClientHello {
			clientRandom = bytes.Clone(body[6:38])
		}
		random := serverRandom.Load()
		if random == nil || header[0] != protocol.RecordAppData {
			return false
		}
		var ok bool
		share, ok = protocol.VerifyAuth(s.cfg.Password, *random, body)
		return ok
	})

	authenticated := errors.Is(err, protocol.ErrAuthenticated)
	if authenticated {
		connectionClaimed.Store(true)
	}
	dest.Close()
	<-camouflageStopped
	if !authenticated || clientRandom == nil {
		return nil, false
	}
	conn, err := protocol.Accept(client, clientReader, s.cfg.Password, clientRandom, *serverRandom.Load(), share)
	return conn, err == nil
}

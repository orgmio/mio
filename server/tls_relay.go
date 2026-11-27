package server

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"sync/atomic"

	"github.com/orgmio/mio/internal/tlsrecord"
	"github.com/orgmio/mio/protocol"
)

// maxAuthAttempts 是握手后最多拿来尝试认证的客户端 Application Data 记录数。
// 认证记录紧跟在客户端的 Finished 之后，超过这个数还没认证的连接不会再认证，之后只做原样转发。
const maxAuthAttempts = 8

// closeWrite 只关闭 conn 的发送方向，把对端的 FIN 传递过去；conn 不支持半关闭时整个关闭。
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	conn.Close()
}

// relay 在客户端与真站之间转发 TLS 记录，直到客户端发来合法的认证记录，之后返回加密会话。
func (s *Server) relay(client, dest net.Conn) (*protocol.Session, bool) {
	clientReader := bufio.NewReaderSize(client, 64<<10)
	var serverRandom atomic.Pointer[[]byte]
	var clientRandom, clientKeyShare []byte // 仅在客户端方向的转发协程中读写
	var shared []byte
	var connectionClaimed atomic.Bool

	camouflageStopped := make(chan struct{})
	go func() {
		defer close(camouflageStopped)
		err := tlsrecord.CopyRecords(client, bufio.NewReaderSize(dest, 32<<10), func(header, body []byte) tlsrecord.Action {
			switch {
			case header[0] == tlsrecord.TypeHandshake && len(body) >= 38 && body[0] == tlsrecord.HandshakeServerHello:
				// 遇到 HelloRetryRequest 时会有两条 ServerHello，以最后一条为准。
				random := bytes.Clone(body[6:38])
				serverRandom.Store(&random)
			case header[0] == tlsrecord.TypeAppData:
				// Application Data 只会出现在 ServerHello 之后，后面的内容不必再解析。
				return tlsrecord.Passthrough
			}
			return tlsrecord.Forward
		})
		switch {
		case connectionClaimed.Load():
		case tlsrecord.CleanEOF(err):
			// 真站只是不再发送，客户端仍可能在发，像真站那样只半关闭。
			closeWrite(client)
		default:
			client.Close()
		}
	}()

	attempts := 0
	err := tlsrecord.CopyRecords(dest, clientReader, func(header, body []byte) tlsrecord.Action {
		// 只取第一条 ClientHello：HelloRetryRequest 之后客户端会换一个 key_share，而它的认证密钥是用第一个算的。
		if clientRandom == nil && header[0] == tlsrecord.TypeHandshake && len(body) >= 38 && body[0] == tlsrecord.HandshakeClientHello {
			clientRandom = bytes.Clone(body[6:38])
			clientKeyShare, _ = tlsrecord.X25519KeyShare(body)
		}
		if header[0] != tlsrecord.TypeAppData {
			return tlsrecord.Forward
		}
		random := serverRandom.Load()
		if random == nil || clientKeyShare == nil {
			return tlsrecord.Passthrough
		}
		var ok bool
		if shared, ok = protocol.VerifyAuth(s.key, clientKeyShare, clientRandom, *random, header, body); ok {
			return tlsrecord.Claim
		}
		if attempts++; attempts >= maxAuthAttempts {
			return tlsrecord.Passthrough
		}
		return tlsrecord.Forward
	})

	authenticated := errors.Is(err, tlsrecord.ErrAuthenticated)
	switch {
	case authenticated:
		connectionClaimed.Store(true)
	case tlsrecord.CleanEOF(err):
		// 客户端只是不再发送：把 FIN 传给真站，等它把该回的内容回完，和直接访问真站时一样。
		closeWrite(dest)
		<-camouflageStopped
	}
	dest.Close()
	<-camouflageStopped
	if !authenticated || clientRandom == nil {
		return nil, false
	}
	session, err := protocol.Accept(client, clientReader, shared, clientRandom, *serverRandom.Load())
	return session, err == nil
}

package protocol

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/orgmio/mio/config"
)

const readyTimeout = 3 * time.Second

// Handshake 经服务端中转与真站完成 TLS 握手，随即发送认证记录，并在 readyTimeout 内等待服务端的就绪帧。
func Handshake(ctx context.Context, raw net.Conn, peer config.Peer) (net.Conn, error) {
	conn := utls.UClient(raw, &utls.Config{ServerName: peer.Dest}, utls.HelloChrome_Auto)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	clientRandom := conn.HandshakeState.Hello.Random
	serverRandom := conn.HandshakeState.ServerHello.Random

	keys, err := newClientKeys()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}
	record, err := authRecord(peer.Password, serverRandom, keys.share())
	if err != nil {
		return nil, fmt.Errorf("build auth record: %w", err)
	}
	if _, err := raw.Write(record); err != nil {
		return nil, fmt.Errorf("send auth record: %w", err)
	}

	send, recv, err := transportAEADs(peer.Password, nil, clientRandom, serverRandom, true)
	if err != nil {
		return nil, fmt.Errorf("derive transport keys: %w", err)
	}
	secure := newEncrypt(raw, bufio.NewReader(raw), send, recv)

	if err := raw.SetReadDeadline(time.Now().Add(readyTimeout)); err != nil {
		return nil, err
	}
	reply, err := secure.waitReady()
	if err != nil {
		return nil, fmt.Errorf("wait server ready: %w", err)
	}
	secret, err := keys.finish(reply)
	if err != nil {
		return nil, fmt.Errorf("key exchange: %w", err)
	}
	send, recv, err = transportAEADs(peer.Password, secret, clientRandom, serverRandom, true)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}
	secure.rekey(send, recv)
	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return secure, nil
}

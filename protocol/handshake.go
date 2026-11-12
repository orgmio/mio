package protocol

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

const readyTimeout = 3 * time.Second

// Handshake 是客户端握手：经服务端中转与真站完成 TLS 握手，随即发送认证记录，
// 在 readyTimeout 内等待服务端的就绪帧，再用混合密钥交换的结果换成会话密钥。
func Handshake(ctx context.Context, raw net.Conn, peer Peer) (*Conn, error) {
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

	send, recv, err := DeriveKeys(peer.Password, nil, clientRandom, serverRandom, true)
	if err != nil {
		return nil, fmt.Errorf("derive transport keys: %w", err)
	}
	secure := NewConn(raw, bufio.NewReader(raw), send, recv)

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
	send, recv, err = DeriveKeys(peer.Password, secret, clientRandom, serverRandom, true)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}
	secure.rekey(send, recv)
	if err := raw.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return secure, nil
}

// Accept 是服务端握手：对已通过 VerifyAuth 的连接，用密码密钥发出带服务端密钥份额的就绪帧，
// 再切换到混合密钥交换派生的会话密钥。reader 必须是之前读取该连接时用的那个 bufio.Reader。
func Accept(conn net.Conn, reader *bufio.Reader, password string, clientRandom, serverRandom, share []byte) (*Conn, error) {
	reply, secret, err := serverExchange(share)
	if err != nil {
		return nil, err
	}
	send, recv, err := DeriveKeys(password, nil, clientRandom, serverRandom, false)
	if err != nil {
		return nil, err
	}
	enc := NewConn(conn, reader, send, recv)
	if err := enc.writeFrame(FrameReady, reply); err != nil {
		return nil, err
	}
	send, recv, err = DeriveKeys(password, secret, clientRandom, serverRandom, false)
	if err != nil {
		return nil, err
	}
	enc.rekey(send, recv)
	return enc, nil
}

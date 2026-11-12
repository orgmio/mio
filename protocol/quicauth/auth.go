package quicauth

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/orgmio/mio/protocol"
)

const (
	// ExporterLabel 是双方从 QUIC 的 TLS 会话导出 32 字节密钥材料时用的标签。
	ExporterLabel = "mio quic auth"
	// Timeout 是握手后完成认证的时限。
	Timeout = 5 * time.Second

	// ClientMessageSize 是客户端在首个 stream 上发出的认证消息长度：临时公钥(32) ‖ 客户端证明(32)。
	ClientMessageSize = 64
	// ServerMessageSize 是服务端回复的证明长度。
	ServerMessageSize = 32
)

// authKey 由临时公钥与服务端静态密钥的 X25519 共享密钥、TLS 导出密钥派生，绑定到这条 QUIC 连接。
func authKey(shared, exporter []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, exporter, "mio quic auth "+protocol.Version, 32)
}

func proof(key []byte, label string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	return mac.Sum(nil)
}

// ClientAuth 生成客户端认证消息，并返回服务端应当回复的证明。
// 只有持有服务端私钥的一方能算出正确的回复，所以客户端校验回复即可确认对端身份。
func ClientAuth(server *ecdh.PublicKey, exporter []byte) (message, expectedReply []byte, err error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err := ephemeral.ECDH(server)
	if err != nil {
		return nil, nil, err
	}
	key, err := authKey(shared, exporter)
	if err != nil {
		return nil, nil, err
	}
	message = append(ephemeral.PublicKey().Bytes(), proof(key, "client")...)
	return message, proof(key, "server"), nil
}

// ServerAuth 校验客户端认证消息，通过时返回要回复给客户端的证明。
func ServerAuth(key *ecdh.PrivateKey, exporter, message []byte) ([]byte, error) {
	if len(message) != ClientMessageSize {
		return nil, errors.New("invalid client auth message")
	}
	pub, err := ecdh.X25519().NewPublicKey(message[:32])
	if err != nil {
		return nil, err
	}
	shared, err := key.ECDH(pub)
	if err != nil {
		return nil, err
	}
	k, err := authKey(shared, exporter)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(message[32:], proof(k, "client")) {
		return nil, errors.New("client proof mismatch")
	}
	return proof(k, "server"), nil
}

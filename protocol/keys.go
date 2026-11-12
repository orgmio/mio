package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

const (
	labelClientToServer = "mio c2s"
	labelServerToClient = "mio s2c"
)

// DeriveKeys 派生两个方向各自独立的 AES-256-GCM 密钥：
//
//	ikm  = secret ‖ password
//	salt = clientRandom ‖ serverRandom
//	key  = HKDF-SHA256(ikm, salt, "mio c2s" 或 "mio s2c", 32)
//
// secret 为 nil 时只用密码，这组密钥只用于服务端发出的 ready 帧。
// isClient 决定返回值里哪个方向是 send、哪个是 recv。
func DeriveKeys(password string, secret, clientRandom, serverRandom []byte, isClient bool) (send, recv cipher.AEAD, err error) {
	salt := append(append([]byte{}, clientRandom...), serverRandom...)
	ikm := append(append([]byte{}, secret...), password...)
	c2s, err := newGCM(ikm, salt, labelClientToServer)
	if err != nil {
		return nil, nil, err
	}
	s2c, err := newGCM(ikm, salt, labelServerToClient)
	if err != nil {
		return nil, nil, err
	}
	if isClient {
		return c2s, s2c, nil
	}
	return s2c, c2s, nil
}

func newGCM(ikm, salt []byte, label string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, ikm, salt, label, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// nonce 把记录序号按大端写进 nonce 的最后 8 字节，其余为 0。
func nonce(aead cipher.AEAD, seq uint64) []byte {
	n := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(n[len(n)-8:], seq)
	return n
}

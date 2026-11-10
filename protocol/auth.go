package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"github.com/orgmio/mio/protocol/padding"
)

const (
	protocolVersion = 2
	authLabel       = "mio auth"
)

// authAEAD 的密钥由密码和真站给出的 server_random 派生，换一条连接就无法重放。
func authAEAD(password string, serverRandom []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(password), serverRandom, authLabel, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// authRecord 生成伪装成 TLS Application Data 的认证记录：版本号、客户端密钥份额与随机填充的 AEAD 密文，一次性 nonce 固定为 0。
func authRecord(password string, serverRandom, share []byte) ([]byte, error) {
	aead, err := authAEAD(password, serverRandom)
	if err != nil {
		return nil, err
	}
	paddingLength, err := padding.RandomInt(32, 1024)
	if err != nil {
		return nil, err
	}
	paddingBytes, err := padding.RandomBytes(paddingLength)
	if err != nil {
		return nil, err
	}
	plain := append(append([]byte{protocolVersion}, share...), paddingBytes...)

	body := aead.Seal(nil, make([]byte, aead.NonceSize()), plain, nil)
	record := []byte{RecordAppData, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(record[3:], uint16(len(body)))
	return append(record, body...), nil
}

// VerifyAuth 能用密码派生的密钥解开并且版本号正确，就是认证通过，同时返回客户端密钥份额。
func VerifyAuth(password string, serverRandom, body []byte) ([]byte, bool) {
	aead, err := authAEAD(password, serverRandom)
	if err != nil {
		return nil, false
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), body, nil)
	if err != nil || len(plain) < 1+clientShareSize+32 || len(plain) > 1+clientShareSize+1024 || plain[0] != protocolVersion {
		return nil, false
	}
	return plain[1 : 1+clientShareSize], true
}

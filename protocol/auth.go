package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"

	"github.com/orgmio/mio/internal/tlsrecord"
	"github.com/orgmio/mio/protocol/padding"
)

// authLabel 带上完整版本号：版本不同的两端算出的密钥不同，认证必然失败。
const authLabel = "mio auth " + Version

// authAEAD 的密钥由共享密钥、版本号和双方 random 派生；server_random 由真站给出，换一条连接就无法重放。
func authAEAD(shared, clientRandom, serverRandom []byte) (cipher.AEAD, error) {
	salt := append(append([]byte{}, clientRandom...), serverRandom...)
	key, err := hkdf.Key(sha256.New, shared, salt, authLabel, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// authRecord 生成伪装成 TLS Application Data 的认证记录：客户端密钥份额与随机填充的 AEAD 密文，
// 5 字节记录头作为附加数据，一次性 nonce 固定为 0。
func authRecord(shared, clientRandom, serverRandom, share []byte) ([]byte, error) {
	aead, err := authAEAD(shared, clientRandom, serverRandom)
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
	plain := append(append([]byte{}, share...), paddingBytes...)

	header := []byte{tlsrecord.TypeAppData, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(plain)+aead.Overhead()))
	record := append([]byte(nil), header...)
	return aead.Seal(record, make([]byte, aead.NonceSize()), plain, header), nil
}

// VerifyAuth 是服务端认证：用服务端私钥与客户端 ClientHello 里的 X25519 key_share 算出共享密钥，
// 能解开认证记录（header 为其 5 字节记录头）即认证通过。返回共享密钥与客户端密钥份额，交给 Accept。
func VerifyAuth(key *ecdh.PrivateKey, clientKeyShare, clientRandom, serverRandom, header, body []byte) (shared, share []byte, ok bool) {
	pub, err := ecdh.X25519().NewPublicKey(clientKeyShare)
	if err != nil {
		return nil, nil, false
	}
	shared, err = key.ECDH(pub)
	if err != nil {
		return nil, nil, false
	}
	aead, err := authAEAD(shared, clientRandom, serverRandom)
	if err != nil {
		return nil, nil, false
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), body, header)
	if err != nil || len(plain) < clientShareSize+32 || len(plain) > clientShareSize+1024 {
		return nil, nil, false
	}
	return shared, plain[:clientShareSize], true
}

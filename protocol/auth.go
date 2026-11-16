package protocol

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

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

// 握手后客户端紧接着发出两条记录，长度上对应浏览器在 HTTP/2 连接开头发出的两条记录：
// 认证记录对应连接前言与 SETTINGS、WINDOW_UPDATE 帧所在的那条小记录，份额记录对应第一个请求。
const (
	// authPlainSize 是认证记录明文的长度，加上 16 字节 tag 后记录体为 87 字节。
	// 用 Brave 157（Chromium 157）实测，HTTP/2 连接上握手后的第一条记录固定是这个长度。
	authPlainSize = 71
	// maxAuthPlain 是服务端接受的认证记录明文长度上限。
	maxAuthPlain = 256
	// maxSharePadding 是份额记录里随机填充的最大长度。
	maxSharePadding = 255
)

// sealRecord 把 plain 加密成一条伪装成 TLS Application Data 的记录，5 字节记录头作为附加数据。
func sealRecord(aead cipher.AEAD, seq uint64, plain []byte) []byte {
	header := []byte{tlsrecord.TypeAppData, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(plain)+aead.Overhead()))
	record := append([]byte(nil), header...)
	return aead.Seal(record, nonce(aead, seq), plain, header)
}

// authRecords 生成客户端在握手后发出的两条记录，用同一把认证密钥加密，nonce 依次为 0 和 1：
// 第一条是认证记录，明文只有随机填充，能解开它就说明对方算得出共享密钥；
// 第二条是份额记录，明文为客户端密钥份额加随机填充。
func authRecords(shared, clientRandom, serverRandom, share []byte) ([]byte, error) {
	aead, err := authAEAD(shared, clientRandom, serverRandom)
	if err != nil {
		return nil, err
	}
	authPlain, err := padding.RandomBytes(authPlainSize)
	if err != nil {
		return nil, err
	}
	paddingLength, err := padding.RandomInt(0, maxSharePadding)
	if err != nil {
		return nil, err
	}
	paddingBytes, err := padding.RandomBytes(paddingLength)
	if err != nil {
		return nil, err
	}
	sharePlain := append(append([]byte{}, share...), paddingBytes...)
	return append(sealRecord(aead, 0, authPlain), sealRecord(aead, 1, sharePlain)...), nil
}

// VerifyAuth 是服务端认证：用服务端私钥与客户端 ClientHello 里的 X25519 key_share 算出共享密钥，
// 能解开认证记录（header 为其 5 字节记录头）即认证通过。返回的共享密钥交给 Accept。
func VerifyAuth(key *ecdh.PrivateKey, clientKeyShare, clientRandom, serverRandom, header, body []byte) (shared []byte, ok bool) {
	// 长度不可能是认证记录的直接跳过，不为它做 X25519。
	if len(body) < 16 || len(body) > maxAuthPlain+16 {
		return nil, false
	}
	pub, err := ecdh.X25519().NewPublicKey(clientKeyShare)
	if err != nil {
		return nil, false
	}
	shared, err = key.ECDH(pub)
	if err != nil {
		return nil, false
	}
	aead, err := authAEAD(shared, clientRandom, serverRandom)
	if err != nil {
		return nil, false
	}
	plain, err := aead.Open(nil, nonce(aead, 0), body, header)
	if err != nil || len(plain) > maxAuthPlain {
		return nil, false
	}
	return shared, true
}

// readShare 读取紧跟在认证记录后面的份额记录，返回客户端密钥份额。
func readShare(reader *bufio.Reader, shared, clientRandom, serverRandom []byte) ([]byte, error) {
	aead, err := authAEAD(shared, clientRandom, serverRandom)
	if err != nil {
		return nil, err
	}
	header := make([]byte, tlsrecord.HeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if !tlsrecord.ValidHeader(header) || header[0] != tlsrecord.TypeAppData {
		return nil, errors.New("invalid share record header")
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce(aead, 1), body, header)
	if err != nil || len(plain) < clientShareSize {
		return nil, errors.New("invalid share record")
	}
	return plain[:clientShareSize], nil
}

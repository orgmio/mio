package protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// 密钥用不带填充的 URL 安全 base64 编码（43 个字符），与 sing-box、Xray 的 REALITY 密钥格式相同。
var keyEncoding = base64.RawURLEncoding

// GenerateKeyPair 生成服务端的 X25519 静态密钥对，返回编码后的私钥（服务端用）与公钥（客户端用）。
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return keyEncoding.EncodeToString(key.Bytes()), keyEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// ParsePrivateKey 解析 GenerateKeyPair 生成的私钥。
func ParsePrivateKey(s string) (*ecdh.PrivateKey, error) {
	raw, err := keyEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("invalid private key: want 43 base64url characters (run `mio keygen`)")
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// ParsePublicKey 解析 GenerateKeyPair 生成的公钥。
func ParsePublicKey(s string) (*ecdh.PublicKey, error) {
	raw, err := keyEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("invalid public key: want 43 base64url characters (run `mio keygen`)")
	}
	return ecdh.X25519().NewPublicKey(raw)
}

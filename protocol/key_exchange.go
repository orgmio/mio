package protocol

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
)

const (
	x25519Size = 32
	// 客户端份额：X25519 公钥 + ML-KEM-768 封装公钥；服务端份额：X25519 公钥 + ML-KEM-768 密文。
	clientShareSize = x25519Size + mlkem.EncapsulationKeySize768
	serverShareSize = x25519Size + mlkem.CiphertextSize768
)

// clientKeys 是客户端本次连接的临时密钥，对应 TLS 的 X25519MLKEM768 混合方案。
type clientKeys struct {
	x25519 *ecdh.PrivateKey
	mlkem  *mlkem.DecapsulationKey768
}

func newClientKeys() (*clientKeys, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &clientKeys{x25519: x, mlkem: k}, nil
}

func (k *clientKeys) share() []byte {
	return append(k.x25519.PublicKey().Bytes(), k.mlkem.EncapsulationKey().Bytes()...)
}

// finish 用服务端份额算出共享密钥。
func (k *clientKeys) finish(reply []byte) ([]byte, error) {
	if len(reply) != serverShareSize {
		return nil, errors.New("invalid server share")
	}
	pub, err := ecdh.X25519().NewPublicKey(reply[:x25519Size])
	if err != nil {
		return nil, err
	}
	xss, err := k.x25519.ECDH(pub)
	if err != nil {
		return nil, err
	}
	kss, err := k.mlkem.Decapsulate(reply[x25519Size:])
	if err != nil {
		return nil, err
	}
	return append(xss, kss...), nil
}

// serverExchange 处理客户端份额，返回要发回的服务端份额与共享密钥。
func serverExchange(share []byte) (reply, secret []byte, err error) {
	if len(share) != clientShareSize {
		return nil, nil, errors.New("invalid client share")
	}
	pub, err := ecdh.X25519().NewPublicKey(share[:x25519Size])
	if err != nil {
		return nil, nil, err
	}
	ek, err := mlkem.NewEncapsulationKey768(share[x25519Size:])
	if err != nil {
		return nil, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	xss, err := priv.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	kss, ct := ek.Encapsulate()
	return append(priv.PublicKey().Bytes(), ct...), append(xss, kss...), nil
}

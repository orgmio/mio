package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

type initialStatus int

const (
	initialNone       initialStatus = iota // 不是能解开的 QUIC v1 客户端 Initial 包
	initialIncomplete                      // 能解开，但这个包里还看不到 ClientHello 的开头
	initialRandom                          // 已取得 ClientHello.random
)

var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}

func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, _ := hkdf.Expand(sha256.New, secret, string(info), length)
	return out
}

// initialClientHelloRandom 按 RFC 9001 用 DCID 派生 Initial 密钥，解开客户端首包并取出 ClientHello.random。不修改 pkt。
func initialClientHelloRandom(pkt []byte) ([]byte, initialStatus) {
	// 客户端的 Initial 数据报必须填充到至少 1200 字节。
	if len(pkt) < 1200 || pkt[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(pkt[1:5]) != 1 {
		return nil, initialNone
	}
	i := 5
	dcidLen := int(pkt[i])
	i++
	if dcidLen > 20 || i+dcidLen >= len(pkt) {
		return nil, initialNone
	}
	dcid := pkt[i : i+dcidLen]
	i += dcidLen
	scidLen := int(pkt[i])
	i += 1 + scidLen
	if i >= len(pkt) {
		return nil, initialNone
	}
	tokenLen, n := readVarint(pkt[i:])
	if n == 0 {
		return nil, initialNone
	}
	i += n + int(tokenLen)
	if i >= len(pkt) {
		return nil, initialNone
	}
	length, n := readVarint(pkt[i:])
	if n == 0 {
		return nil, initialNone
	}
	pnOffset := i + n
	end := pnOffset + int(length)
	if end > len(pkt) || pnOffset+20 > end {
		return nil, initialNone
	}

	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		return nil, initialNone
	}
	secret := expandLabel(initialSecret, "client in", 32)
	key := expandLabel(secret, "quic key", 16)
	iv := expandLabel(secret, "quic iv", 12)
	hp := expandLabel(secret, "quic hp", 16)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, initialNone
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], pkt[pnOffset+4:pnOffset+20])

	packet := append([]byte(nil), pkt[:end]...)
	packet[0] ^= mask[0] & 0x0f
	pnLen := int(packet[0]&0x03) + 1
	var pn uint64
	for j := 0; j < pnLen; j++ {
		packet[pnOffset+j] ^= mask[1+j]
		pn = pn<<8 | uint64(packet[pnOffset+j])
	}
	nonce := append([]byte(nil), iv...)
	for j := 0; j < 8; j++ {
		nonce[11-j] ^= byte(pn >> (8 * j))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, initialNone
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, initialNone
	}
	plain, err := aead.Open(nil, nonce, packet[pnOffset+pnLen:], packet[:pnOffset+pnLen])
	if err != nil {
		return nil, initialNone
	}

	chunks := map[uint64][]byte{}
parse:
	for len(plain) > 0 {
		switch plain[0] {
		case 0x00, 0x01: // PADDING、PING
			plain = plain[1:]
		case 0x06: // CRYPTO
			offset, n1 := readVarint(plain[1:])
			size, n2 := readVarint(plain[1+max(n1, 0):])
			start := 1 + n1 + n2
			if n1 == 0 || n2 == 0 || start+int(size) > len(plain) {
				break parse
			}
			chunks[offset] = plain[start : start+int(size)]
			plain = plain[start+int(size):]
		default:
			break parse
		}
	}

	var data []byte
	for {
		chunk := chunks[uint64(len(data))]
		if len(chunk) == 0 {
			break
		}
		data = append(data, chunk...)
	}
	// ClientHello：类型(1) 长度(3) 版本(2) random(32)
	if len(data) < 38 || data[0] != 0x01 {
		return nil, initialIncomplete
	}
	return data[6:38], initialRandom
}

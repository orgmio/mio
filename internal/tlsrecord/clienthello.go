package tlsrecord

import "encoding/binary"

const (
	extensionKeyShare = 0x0033
	groupX25519       = 0x001d
)

// X25519KeyShare 从 ClientHello 握手消息（以消息类型字节开头）中取出 X25519 的 key_share 公钥。
// ClientHello 不完整或没有 X25519 份额时 ok 为 false。
func X25519KeyShare(msg []byte) (share []byte, ok bool) {
	r := reader(msg)
	if t, ok := r.u8(); !ok || t != HandshakeClientHello {
		return nil, false
	}
	length, ok := r.u24()
	if !ok || length > len(r) {
		return nil, false
	}
	r = r[:length]
	// legacy_version(2) random(32)
	if !r.skip(2 + 32) {
		return nil, false
	}
	if n, ok := r.u8(); !ok || !r.skip(n) { // legacy_session_id
		return nil, false
	}
	if n, ok := r.u16(); !ok || !r.skip(n) { // cipher_suites
		return nil, false
	}
	if n, ok := r.u8(); !ok || !r.skip(n) { // legacy_compression_methods
		return nil, false
	}
	n, ok := r.u16()
	if !ok || n > len(r) {
		return nil, false
	}
	exts := r[:n]
	for len(exts) > 0 {
		typ, ok1 := exts.u16()
		size, ok2 := exts.u16()
		if !ok1 || !ok2 || size > len(exts) {
			return nil, false
		}
		body := exts[:size]
		exts = exts[size:]
		if typ != extensionKeyShare {
			continue
		}
		total, ok := body.u16()
		if !ok || total > len(body) {
			return nil, false
		}
		shares := body[:total]
		for len(shares) > 0 {
			group, ok1 := shares.u16()
			keyLength, ok2 := shares.u16()
			if !ok1 || !ok2 || keyLength > len(shares) {
				return nil, false
			}
			key := shares[:keyLength]
			shares = shares[keyLength:]
			if group == groupX25519 && keyLength == 32 {
				return append([]byte(nil), key...), true
			}
		}
		return nil, false
	}
	return nil, false
}

type reader []byte

func (r *reader) u8() (int, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := int((*r)[0])
	*r = (*r)[1:]
	return v, true
}

func (r *reader) u16() (int, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := int(binary.BigEndian.Uint16(*r))
	*r = (*r)[2:]
	return v, true
}

func (r *reader) u24() (int, bool) {
	if len(*r) < 3 {
		return 0, false
	}
	v := int((*r)[0])<<16 | int((*r)[1])<<8 | int((*r)[2])
	*r = (*r)[3:]
	return v, true
}

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

// Package quicauth 实现 mio QUIC 路径的认证：ClientHello.random 里的标记，以及握手后基于服务端静态密钥的双向认证。
package quicauth

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol"
)

const (
	markerNonceSize = 16
	markerTagSize   = 16
	markerRetention = 5 * time.Minute // 标记最多约 3 分钟有效，留出余量
)

// markerKey 由服务端公钥派生：不知道公钥就造不出、也验证不了标记，而公钥是 256 位随机值，无法离线猜测。
func markerKey(server *ecdh.PublicKey) []byte {
	key, err := hkdf.Key(sha256.New, server.Bytes(), nil, "mio quic marker "+protocol.Version, 32)
	if err != nil {
		panic(err) // 只会因长度参数非法而失败，这里是常量
	}
	return key
}

func markerTag(key, nonce []byte, minute uint64) []byte {
	var m [8]byte
	binary.BigEndian.PutUint64(m[:], minute)
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write(m[:])
	return mac.Sum(nil)[:markerTagSize]
}

// NewMarker 生成放进 ClientHello.random 的 32 字节标记：随机数加带分钟时间戳的 HMAC。
func NewMarker(server *ecdh.PublicKey) ([32]byte, error) {
	var marker [32]byte
	if _, err := rand.Read(marker[:markerNonceSize]); err != nil {
		return marker, err
	}
	minute := uint64(time.Now().Unix() / 60)
	copy(marker[markerNonceSize:], markerTag(markerKey(server), marker[:markerNonceSize], minute))
	return marker, nil
}

// ReplayCache 校验标记，并记住近期用过的标记随机数，防止被录下的 Initial 包重放。
type ReplayCache struct {
	key  []byte
	mu   sync.Mutex
	seen map[[markerNonceSize]byte]time.Time
}

// NewReplayCache 为公钥为 server 的服务端创建标记校验器。
func NewReplayCache(server *ecdh.PublicKey) *ReplayCache {
	return &ReplayCache{key: markerKey(server), seen: make(map[[markerNonceSize]byte]time.Time)}
}

// Check 在标记有效、处于时间窗口内且未被用过时返回 true，并记下它。
func (c *ReplayCache) Check(random []byte) bool {
	if len(random) != markerNonceSize+markerTagSize {
		return false
	}
	nonce, tag := random[:markerNonceSize], random[markerNonceSize:]
	now := time.Now()
	minute := uint64(now.Unix() / 60)
	valid := false
	for _, m := range []uint64{minute, minute - 1, minute + 1} {
		if hmac.Equal(markerTag(c.key, nonce, m), tag) {
			valid = true
			break
		}
	}
	if !valid {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for key, expire := range c.seen {
		if now.After(expire) {
			delete(c.seen, key)
		}
	}
	var key [markerNonceSize]byte
	copy(key[:], nonce)
	if _, dup := c.seen[key]; dup {
		return false
	}
	c.seen[key] = now.Add(markerRetention)
	return true
}

// NewRand 返回给 tls.Config.Rand 用的随机源：TLS 库第一次读 32 字节（即 ClientHello.random）时得到 marker。
func NewRand(marker [32]byte) io.Reader { return &markerRand{marker: marker} }

type markerRand struct {
	mu     sync.Mutex
	marker [32]byte
	used   bool
}

func (r *markerRand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.used && len(p) == len(r.marker) {
		r.used = true
		return copy(p, r.marker[:]), nil
	}
	return rand.Read(p)
}

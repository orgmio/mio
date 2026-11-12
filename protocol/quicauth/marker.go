// Package quicauth 实现 mio QUIC 路径的认证：ClientHello.random 里的标记与绑定 TLS 导出密钥的证明。
package quicauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

const (
	markerNonceSize = 16
	markerTagSize   = 16
	markerRetention = 5 * time.Minute // 标记最多约 3 分钟有效，留出余量

	ExporterLabel = "mio quic auth"
	ClientLabel   = "mio quic client"
	ServerLabel   = "mio quic server"
	Timeout       = 5 * time.Second
)

func markerTag(password string, nonce []byte, minute uint64) []byte {
	var m [8]byte
	binary.BigEndian.PutUint64(m[:], minute)
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("mio quic marker"))
	mac.Write(nonce)
	mac.Write(m[:])
	return mac.Sum(nil)[:markerTagSize]
}

// NewMarker 生成放进 ClientHello.random 的 32 字节标记：随机数加带分钟时间戳的 HMAC。
func NewMarker(password string) ([32]byte, error) {
	var marker [32]byte
	if _, err := rand.Read(marker[:markerNonceSize]); err != nil {
		return marker, err
	}
	minute := uint64(time.Now().Unix() / 60)
	copy(marker[markerNonceSize:], markerTag(password, marker[:markerNonceSize], minute))
	return marker, nil
}

// ReplayCache 记住近期用过的标记随机数，防止被录下的 Initial 包重放。
type ReplayCache struct {
	mu   sync.Mutex
	seen map[[markerNonceSize]byte]time.Time
}

func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: make(map[[markerNonceSize]byte]time.Time)}
}

// Check 在标记有效、处于时间窗口内且未被用过时返回 true，并记下它。
func (c *ReplayCache) Check(password string, random []byte) bool {
	if len(random) != markerNonceSize+markerTagSize {
		return false
	}
	nonce, tag := random[:markerNonceSize], random[markerNonceSize:]
	now := time.Now()
	minute := uint64(now.Unix() / 60)
	valid := false
	for _, m := range []uint64{minute, minute - 1, minute + 1} {
		if hmac.Equal(markerTag(password, nonce, m), tag) {
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

// Proof 用密码和 TLS 导出密钥算出认证证明，绑定到这条 QUIC 连接，防止中间人转发。
func Proof(password, label string, exporter []byte) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte(label))
	mac.Write(exporter)
	return mac.Sum(nil)
}

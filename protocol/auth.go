// Package protocol 实现 ixa 协议的核心认证机制。
//
// 设计目标：
//   - 客户端在 TLS ClientHello.Random（32 字节）中嵌入一个可被服务端验证、
//     但对第三方观察者而言与真随机数无法区分的 HMAC 摘要。
//   - 服务端收到 ClientHello 后，在完成任何 TLS 握手动作之前，仅凭这 32 字节
//     明文即可判断"这是我的客户端"还是"这是路人/主动探测流量"。
//   - 引入时间窗口做重放缓解：摘要的输入包含被截断到分钟粒度的时间戳，
//     服务端校验时允许一定的时钟偏移容差。
//
// 安全说明：
//   - 时间窗口本身不能替代重放保护的全部工作——同一个窗口内重放仍然有效，
//     这是有意为之的权衡（避免维护滑动窗口/nonce 缓存的状态），窗口越短
//     重放窗口越小，但对客户端-服务端的时钟同步要求越高。
//   - key 必须是密码学随机生成的高熵字节（参见项目 README 的 openssl 建议），
//     绝不能是人类可记忆的口令，因为这里没有像 TLS-SRP 那样的密钥拉伸步骤。
package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
)

// TimeWindowSeconds 定义 HMAC 摘要绑定的时间粒度。
// 客户端和服务端都将 unix 时间戳向下取整到该粒度后再参与计算。
const TimeWindowSeconds = 60

// WindowTolerance 定义服务端校验时，允许客户端时间偏移的窗口数量（向前/向后各多少个窗口）。
// 例如 WindowTolerance=2 时，服务端会尝试 [-2,-1,0,+1,+2] 共 5 个窗口，
// 即最大容忍 ±120 秒的时钟偏差。
const WindowTolerance = 2

// randomFieldSize 是 TLS ClientHello.Random 字段的固定长度（RFC 8446 4.1.2）。
const randomFieldSize = 32

// GenerateClientRandom 生成一个可用作 TLS ClientHello.Random 的 32 字节值，
// 其内容是 HMAC-SHA256(key, windowIndex) 的前 32 字节（SHA256 摘要正好 32 字节，无需截断）。
//
// windowIndex 由调用方传入的 unixTime 计算得出，便于测试时注入固定时间。
func GenerateClientRandom(key []byte, unixTime int64) [randomFieldSize]byte {
	window := unixTime / TimeWindowSeconds
	return computeDigest(key, window)
}

// VerifyServerRandom 在服务端侧校验收到的 ClientHello.Random 是否是用相同 key
// 在允许的时间容差内生成的。返回 true 表示认证通过，应将该连接当作 ixa 隧道接管；
// 返回 false 表示应该原样转发到伪装用的真实后端（例如反代 caddy 的 SNI）。
//
// 使用常量时间比较（crypto/subtle）以避免通过响应时间侧信道泄露 key 的部分信息。
func VerifyServerRandom(key []byte, received [randomFieldSize]byte, unixTime int64) bool {
	centerWindow := unixTime / TimeWindowSeconds
	for delta := -WindowTolerance; delta <= WindowTolerance; delta++ {
		expected := computeDigest(key, centerWindow+int64(delta))
		if subtle.ConstantTimeCompare(expected[:], received[:]) == 1 {
			return true
		}
	}
	return false
}

// computeDigest 是 GenerateClientRandom / VerifyServerRandom 共用的核心计算逻辑，
// 确保两端算法严格一致。
func computeDigest(key []byte, window int64) [randomFieldSize]byte {
	var windowBytes [8]byte
	binary.BigEndian.PutUint64(windowBytes[:], uint64(window))

	mac := hmac.New(sha256.New, key)
	// 固定的 context 前缀，防止该 HMAC 的输出被跨协议/跨用途重用
	// （domain separation，避免与项目未来可能新增的其他 HMAC 用途发生密钥重用冲突）。
	mac.Write([]byte("ixa-go:client-random:v1"))
	mac.Write(windowBytes[:])
	sum := mac.Sum(nil) // 32 字节，恰好等于 randomFieldSize

	var out [randomFieldSize]byte
	copy(out[:], sum)
	return out
}

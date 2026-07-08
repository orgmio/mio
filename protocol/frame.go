package protocol

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// AuthFrameVersion 是当前认证帧格式的版本号，用于未来协议升级时的兼容性判断。
const AuthFrameVersion byte = 1

// AuthFrameSize 是认证帧的固定总长度（1 + 8 + 32 字节）。
const AuthFrameSize = 1 + 8 + 32

// AuthFrameMaxSkew 定义服务端接受的认证帧时间戳与本地时间的最大偏差。
// 与 ClientHello.Random 的窗口机制不同，这里直接携带精确时间戳（已被 TLS 加密保护，
// 不用担心时间戳被观察者利用做流量分析），因此可以设置更精确的容差。
const AuthFrameMaxSkew = 30 * time.Second

// BuildAuthFrame 构造握手完成后要通过 TLS 隧道发送的认证帧。
func BuildAuthFrame(key []byte, now time.Time) []byte {
	buf := make([]byte, AuthFrameSize)
	buf[0] = AuthFrameVersion
	binary.BigEndian.PutUint64(buf[1:9], uint64(now.Unix()))

	tag := authFrameTag(key, buf[:9])
	copy(buf[9:], tag)
	return buf
}

// ParseAndVerifyAuthFrame 解析并校验收到的认证帧。
// 返回 nil error 表示认证通过；否则返回具体的失败原因（调用方应据此立即断开连接，
// 不应向客户端泄露具体是哪一步校验失败，以避免帮助攻击者做 oracle 攻击）。
func ParseAndVerifyAuthFrame(key []byte, frame []byte, now time.Time) error {
	if len(frame) != AuthFrameSize {
		return fmt.Errorf("ixa: invalid auth frame length %d, want %d", len(frame), AuthFrameSize)
	}
	if frame[0] != AuthFrameVersion {
		return fmt.Errorf("ixa: unsupported auth frame version %d", frame[0])
	}

	ts := int64(binary.BigEndian.Uint64(frame[1:9]))
	claimedTime := time.Unix(ts, 0)
	skew := now.Sub(claimedTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > AuthFrameMaxSkew {
		return fmt.Errorf("ixa: auth frame timestamp skew %s exceeds max %s", skew, AuthFrameMaxSkew)
	}

	expected := authFrameTag(key, frame[:9])
	if subtle.ConstantTimeCompare(expected, frame[9:]) != 1 {
		return fmt.Errorf("ixa: auth frame HMAC mismatch")
	}
	return nil
}

func authFrameTag(key []byte, header []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("ixa-go:auth-frame:v1"))
	mac.Write(header)
	return mac.Sum(nil)
}

// 供测试/调试使用：判断两个认证帧是否字节相同（非常量时间，仅用于非安全敏感场景）。
func authFramesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

const (
	protocolVersion = 1
	authLabel       = "mio auth"
	tagSize         = sha256.Size
)

// authTag 把密码与本次握手里真站给出的 server_random 绑定，换一条连接就无法重放。
func authTag(password string, serverRandom []byte) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte(authLabel))
	mac.Write(serverRandom)
	return mac.Sum(nil)
}

// authRecord 生成伪装成 TLS Application Data 的认证记录。
func authRecord(password string, serverRandom []byte) []byte {
	body := append([]byte{protocolVersion}, authTag(password, serverRandom)...)
	record := []byte{recordAppData, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(record[3:], uint16(len(body)))
	return append(record, body...)
}

func verifyAuth(password string, serverRandom, body []byte) bool {
	if len(body) != 1+tagSize || body[0] != protocolVersion {
		return false
	}
	return hmac.Equal(body[1:], authTag(password, serverRandom))
}

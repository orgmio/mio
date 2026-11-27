package protocol

import "strings"

// 这里是 mio 的协议版本。
const Version = "1.0.5"

var kdfVersion = protocolKDFVersion(Version)

// KDFVersion 返回认证用的主版本标签。v1 固定沿用 "1.0.0"。
func KDFVersion() string { return kdfVersion }

func protocolKDFVersion(version string) string {
	major, _, _ := strings.Cut(strings.TrimPrefix(version, "v"), ".")
	if major == "" || major[0] == '0' || strings.ContainsFunc(major, func(c rune) bool {
		return c < '0' || c > '9'
	}) {
		panic("invalid mio protocol major version: " + version)
	}
	return major + ".0.0"
}

package protocol

// Peer 是客户端连接 mio 服务端所需的参数。
type Peer struct {
	Server     string // mio 服务端地址
	ServerPort int    // mio 服务端端口（TCP 与 UDP 相同）
	Dest       string // 伪装站域名，用作 TLS 的 SNI，需与服务端的 dest 一致
	Password   string
}

package protocol

// Version 是 mio 的版本号，同时就是协议版本：它参与 TCP 认证密钥与 QUIC 认证的派生，
// 版本号不同的客户端和服务端无法建立连接，升级时必须两端一起升级。
const Version = "0.5.1"

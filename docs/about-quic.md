# QUIC 传输与 SOCKS5

mio 默认允许客户端通过 TCP 或 QUIC 连接 mio 服务端。如果需要只走 TCP，可以在客户端的
`[outbounds]` 下设置 `udp = false`。如果也要停止服务端的 UDP 监听，在服务端的
`[inbounds]` 下设置 `udp = false`。配置详见[配置文件](config.md)。

mio 的 SOCKS5 入口默认接受 TCP CONNECT。在客户端的 `[outbounds]` 下设置
`socks5_udp = true` 后，也接受 UDP ASSOCIATE。UDP 目标需要服务端支持
[UDP 转发扩展](protocol.md#udp-转发扩展)，可以经由 mio 的 TCP 或 QUIC 路径访问。

UDP 数据报在 mio 隧道内通过可靠有序的流传输。代理 HTTP/3 等基于 UDP 的应用时，
隧道内重传可能增加后续数据报的延迟。

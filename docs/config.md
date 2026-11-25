# 配置文件

mio使用 TOML 作为配置文件格式。

- 结构

```toml
[log]
# 客户端
[outbounds]
# 服务端
[inbounds]
```

## 密钥

自版本0.5.1起，mio使用一对密钥。

在服务端运行：

```bash
mio keygen
```

以生成这对预共享密钥。

## 日志

日志配置用于控制mio的日志输出。

```toml
[log]
enable = true
level = "info"
output = "mio.log"
timestamp = true
```

- `enable`：是否启用日志，`true`表示启用，`false`表示禁用。
- `level`：日志级别，可选值为`"debug"`、`"info"`、`"warn"`、`"error"`。
- `output`：日志文件的保存路径，留空则输出到标准错误。
- `timestamp`：是否带完整时间戳，默认`false`。
  为`true`时每条日志以`+0800 2026-11-15 19:00:37`这样的时间开头；
  为`false`时，输出到终端的日志带启动以来的秒数（如`INFO[0012]`），输出到文件的日志不带时间。

## 客户端配置

客户端配置用于设置mio作为客户端时的监听地址和端口。

```toml
[outbounds]
socks_listen = "127.0.0.1"
socks_listen_port = 10808
socks5_udp = false
server = "1.1.1.1"
server_port = 443
udp = true
dest = "one.one.one.one"
public_key = "mio keygen 输出的 PublicKey"
```

- outbounds字段

> 该项目内置的socks5不支持设置密码，因socks5只是一个连接器。

`socks_listen`：本地socks5监听的IP地址。

`socks_listen_port`：本地socks5监听的端口。

`socks5_udp`：选填，默认 `false`。设为 `true` 时，SOCKS5 入口接受 UDP ASSOCIATE 请求，需要 mio 服务端支持 UDP 转发扩展。开启后，即使同时设置 `udp = false`，也可以通过 TCP 隧道转发 UDP 目标。

`server`：远端服务器地址。

`server_port`：远端服务器端口。

`udp`：选填，默认 `true`，允许 mio 客户端通过 UDP 上的 QUIC 连接 mio 服务端。设为 `false` 时，两端之间只使用 TCP。

`dest`：伪装目标地址，可以是域名或IP地址。

`dest_port`：选填。客户端不使用这个值，可以不写。

`public_key`：服务端公钥，即服务端运行`mio keygen`输出的`PublicKey`。

## 服务端配置

服务端配置用于设置mio作为服务端时的监听地址和端口。

```toml
[inbounds]
listen = "0.0.0.0"
listen_port = 443
udp = true
dest = "one.one.one.one"
dest_port = 443
private_key = "mio keygen 输出的 PrivateKey"
```

- inbounds字段

> `dest`需与客户端`[outbounds].dest`一致，否则客户端校验证书会失败。

`listen`：服务端监听的IP地址。

`listen_port`：服务端的 TCP 监听端口。启用 QUIC 时，UDP 使用相同的端口号。

`udp`：选填，默认 `true`，允许服务端监听 UDP 以处理 QUIC 和伪装站回落流量。设为 `false` 时，服务端只监听 TCP。

`dest`：伪装目标地址，可以是域名或IP地址。

`dest_port`：选填，伪装目标端口。填写时转发到这个端口；不填时转发到与`listen_port`相同的端口。

`private_key`：服务端私钥，即`mio keygen`输出的`PrivateKey`。

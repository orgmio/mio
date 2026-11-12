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

mio 不使用密码，而是使用一对密钥。在服务端运行：

```bash
mio keygen
```

输出的`PrivateKey`填进服务端的`[inbounds].private_key`，`PublicKey`填进客户端的`[outbounds].public_key`。

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
- `timestamp`：每条日志是否带时间戳，默认`true`。

## 客户端配置

客户端配置用于设置mio作为客户端时的监听地址和端口。

```toml
[outbounds]
socks_listen = "127.0.0.1"
socks_listen_port = 10808
server = "1.1.1.1"
server_port = 443
dest = "one.one.one.one"
dest_port = 443
public_key = "mio keygen 输出的 PublicKey"
```

- outbounds字段

> 该项目内置的socks5不支持设置密码，因socks5只是一个连接器，请勿监听到公网地址。

`socks_listen`：本地socks5监听的IP地址。

`socks_listen_port`：本地socks5监听的端口。

`server`：远端服务器地址。

`server_port`：远端服务器端口。

`dest`：伪装目标地址，可以是域名或IP地址。

`dest_port`：伪装目标端口。

`public_key`：服务端公钥，即服务端运行`mio keygen`输出的`PublicKey`。

## 服务端配置

服务端配置用于设置mio作为服务端时的监听地址和端口。

```toml
[inbounds]
listen = "0.0.0.0"
listen_port = 443
dest = "one.one.one.one"
dest_port = 443
private_key = "mio keygen 输出的 PrivateKey"
```

- inbounds字段

> 注意：`dest`需与客户端`[outbounds].dest`一致，否则客户端校验证书会失败。

`listen`：服务端监听的IP地址。

`listen_port`：服务端监听的端口，TCP和UDP同时使用。

`dest`：伪装目标地址，可以是域名或IP地址。

`dest_port`：伪装目标端口。

`private_key`：服务端私钥，即`mio keygen`输出的`PrivateKey`，不要泄露给任何人。

> 配置文件中出现未知字段时mio会直接报错，旧版的`[socks5]`、`[peer]`、`[listen]`、`port`、`path`、`password`需要改成上面的新名字。

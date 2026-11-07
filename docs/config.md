# 配置文件

mio使用 TOML 作为配置文件格式。

- 结构

```toml
# 通用
[log]
enable = true
level = "info"
path = "mio.log"
# 针对客户端
[socks5]
listen = "127.0.0.1"
port = 1080

[server]
server = "example.com"
port = 443
dest = "one.one.one.one"
dest_port = 443
password = "your_password"
# 针对服务端
[listen]
listen = "0.0.0.0"
port = 443
dest = "one.one.one.one"
dest_port = 443
password = "your_password"
```

## 日志

日志配置用于控制mio的日志输出。

提供的选项：

```toml
[log]
enable = true
level = "info"
path = "mio.log"
```

- `enable`：是否启用日志，`true`表示启用，`false`表示禁用。
- `level`：日志级别，可选值为`"debug"`、`"info"`、`"warn"`、`"error"`。
- `path`：日志文件的保存路径。

## 客户端配置

客户端配置用于设置mio作为客户端时的监听地址和端口。

提供的选项：

```toml
[socks5]
listen = "127.0.0.1"
port = 1080

[server]
server = "example.com"
port = 443
dest = "one.one.one.one"
dest_port = 443
password = "your_password"
```

- socks5字段

> 该项目内置的socks5不支持设置密码，因socks5只是一个连接器，使用时请注意安全问题。

`listen`：客户端监听的IP地址。

`port`：客户端监听的端口。

- server字段

`server`：远端服务器地址。

`port`：远端服务器端口。

`dest`：伪装目标地址，可以是域名或IP地址。

`dest_port`：伪装目标端口。

`password`：连接密码。

# 服务端配置

服务端配置用于设置mio作为服务端时的监听地址和端口。

提供的选项：

```toml
[listen]
listen = "0.0.0.0"
port = 443
dest = "one.one.one.one"
dest_port = 443
password = "your_password"
```

- listen字段

> 注意：服务端配置中的`dest`和`dest_port`用于伪装流量，确保其与客户端配置一致。

`listen`：服务端监听的IP地址。

`port`：服务端监听的端口。

`dest`：伪装目标地址，可以是域名或IP地址。

`dest_port`：伪装目标端口。

`password`：连接密码。

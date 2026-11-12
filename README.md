# mio代理协议

## 开始

欢迎来到该mio项目的文档页。

一个兼顾性能与抗审查的新型易用代理协议。

## 🚀 特性

- 抗审查: 使用utls来将数据包外观伪装成`Chrome`，并在认证失败时尽可能将数据转发给伪装网站。
- 抗重放攻击：内置`client/server_random`校验机制，有效抵抗重放攻击。
- 证书：像 Reality 一样借用 `dest` 站点，不用自己配置证书，而且完整进行一次真的TLS握手。
- 认证：不用密码，用 `mio keygen` 生成的密钥对。认证密钥由 ClientHello 自带的 X25519 key_share 与服务端公钥算出，没有可供离线爆破的弱口令，中间人也冒充不了服务端；会话密钥再经 X25519MLKEM768 混合交换。认证失败就将后续任何数据包都转发给 `dest`。
- 速度：支持自动升降级HTTP/3，大幅度提升高丢包环境下的速度。
  在HTTP/3不可用时自动退回HTTP/2或HTTP/1.1，以保证在几乎任何恶劣环境下均可顺利使用。

不道德的问题：本项目因为会借用伪装网站的TLS证书，所以我感觉不怎么道德；
如果你不在乎，随便用；如果你在乎，请更换其他温和的协议。

## 🏗️ 配置

使用`mio help`以获取命令行帮助，使用`mio keygen`生成服务端密钥对。

转到 [文档](https://github.com/orgmio/mio/tree/main/docs) 以获取详细说明。

需要服务端和客户端同时开启TCP和UDP才可完整发挥mio的功能。

**客户端和服务端的版本号必须完全一致**，版本号参与认证，不一致就连不上，升级时请两端一起升级。

mio默认禁止向socks5隧道中发送UDP数据，原因和hysteria2一致，
在QUIC里面套QUIC会导致Hysteria2自己的流控无法识别从而出现性能问题。
mio也是同理，而且禁止QUIC对正常上网没有任何影响。

DNS部分，因为该仓库只是一个代理协议的概念验证，

所以解析服务端域名直接使用客户端本地DNS；
解析通过代理的域名和伪装域名均通过服务端DNS进行解析。

## 📦 作为库使用

mio 的加密和帧格式可以直接引用：

```go
import "github.com/orgmio/mio/protocol"
```

线上格式与接口说明见 [协议规范](docs/protocol.md)。

## ⚖️ 条款

此项目基于[Mo Public License](https://867678.xyz/docs/mopl)授权。

引用的其他项目使用他们自身的许可条款。

内置的QUIC-BBR来自Hysteria2，[许可条款](https://github.com/HyNetworks/hysteria/blob/master/core/LICENSE.md)

使用时需遵循您所在地区的法律和上述许可条款，

并，这是一个实验项目，作者不对任何后果承担责任，切勿用于非法用途。

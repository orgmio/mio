# ixa-go

一个简易的跨平台、强伪装、高性能代理协议实现

# 🚀 项目特点

旨在模拟一个chrome浏览器访问一个caddy反代网站

跟Reality相比 此项目弥补了他不支持QUIC协议传输代理的缺点

跟Hysteria相比 此项目弥补了他在遇到UDP不通时无所事事直接连不上的缺点

该仓库只是一个最简实现 以验证协议可行性

# 📚 项目文档

请直接参阅该项目的example.toml文件 里面包含了该项目所有能支持的字段

## 🧪 如何起飞

当前 POC 用 TLS 1.3 和 HMAC-SHA256 验证以下最小链路：

先启动服务端：

```bash
./ixa-go -c example-server.toml
```

再启动客户端：

```bash
./ixa-go -c example-client.toml
curl --socks5-hostname 127.0.0.1:2080 https://example.com
```

此阶段只验证加密、认证、目标封装和双向转发。

目前已实现ClientHello.Random与ServerHello.Random双向隐藏HMAC认证，以及认证失败时回落到sni对应的真实站点。

SOCKS5目前支持TCP CONNECT和UDP ASSOCIATE，UDP在POC阶段以每个数据报建立一次短TLS隧道的方式传输。

服务端启动时会验证并缓存sni站点的真实证书链，客户端通过反向HMAC验证服务端。

尚未实现QUIC、Caddy本地回落和 Brave 指纹模拟，不应用于生产环境。

## 📄 配置文件

`sni`字段必须是一个支持TLS1.3的HTTPS URL，因为需要偷他的证书(没错这就是类Reality);端口可以任意。

# 🏃 协议行为

协议行为旨在模拟`caddy-real/`下存在的wireshark抓包文件

- **way-brave-caddy.pcapng**:brave访问一个空白的caddy的行为
- **way-brave-caddy-baidu.pcapng**:brave访问一个反代了百度的caddy的行为 配置文件在Caddyfile

这个文件夹下是由wireshark抓包的真实brave访问真实caddy的行为

客户端行为旨在模拟ArchLinux源`extra`中带的`Brave`浏览器的无痕模式

只要在公网传输的数据包与wireshark抓到的真实行为无异此项目就算成功

下方为测试时hosts文件中的不同 需注意local.867678.xyz没有真正的权威指向 这是我用来测试的

```ini
local.867678.xyz 127.0.0.1
```

> 一般情况下

| 客户端                                   | 服务端                                   |
| ---------------------------------------- | ---------------------------------------- |
| 尝试用HTTP/1.1+TLS1.3+X25519MLKEM768连接 | 先返回一点虚假数据并告诉客户端我支持QUIC |
| 尝试用HTTP/3+TLS1.3+X25519MLKEM768连接   | 准备接收QUIC                             |
| QUIC建立成功                             | 交换密钥并开始传输加密数据               |

> 失败处理

| 客户端             | 服务端                   |
| ------------------ | ------------------------ |
| 客户端尝试QUIC失败 | 退回HTTP/1.1             |
| 证书验证错误       | 立刻切断连接             |
| 迟迟没有回应       | 超时后关闭连接并重新尝试 |

> 数据外表

应当看起来像是一个brave在访问Caddy（TLS）

需要做到：

```
应用 → SOCKS5 → ixa 客户端 → TLS 隧道 → ixa 服务端 → 目标网站
```

首先尝试HTTP/1.1 TLS握手中服务端将校验TLSClientHello中的HMAC是否为设置的密码

如果是，在建立TCP连接之后开始尝试建立QUIC隧道;QUIC成功之后按照标准QUIC的方式传输;如果不成功按照HTTP/1.1或2的方式传输

如果不是，直接返回伪装域名的内容。

## ⚠️ 安全性警告

为了配置的方便ixa协议并不像reality那样需要一个PublicKey和一个ShortId

所以key字段必须是用密码学工具生成的无关联字符

下列是一个推荐的示例用openssl生成符合要求的密码

```bash
openssl rand -hex 32
```

这里以HMAC（RFC2104）的规范为例
| 长度 单位：字节 | 安全性 |
| ---- | ---- |
| 16 | 刚达到不那么容易破解的临界点 |
| 32 | 现代暴力破解工具一般没辙 |
| 64 | 刚好卡在HMAC的临界点 超过就会被SHA256压缩成32字节 没意义 |

# ⚖️ 条款与授权

该项目以GNU AFFERO GENERAL PUBLIC LICENSE v3授权 详细参见LICENSE

如果您希望二次开发，也可以指定一个更高版本

如果您希望将其集成到诸如Sing-box、xray等内核中，可以修改为GPL-v3或其他

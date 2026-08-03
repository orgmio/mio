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

先启动服务端：

```bash
./ixa-go -c example-server.toml
```

再启动客户端：

```bash
./ixa-go -c example-client.toml
curl --socks5-hostname 127.0.0.1:2080 https://example.com
```

## 📄 配置文件

`sni`字段必须是一个支持TLS1.3的HTTPS URL，因为需要偷他的证书(没错这是类Reality);端口可以任意。

# 🏃 协议行为

协议行为旨在模拟`caddy-real/`下存在的wireshark抓包文件

- **way-ixa.pcapng**:我前前后后用他访问了 B站 ip.cn ip138.com bing.com www.gov.cn 以及中间不小心触发了两次谷歌搜索
- **way-brave-caddy-baidu.pcapng**:brave访问一个反代了百度的caddy的行为 配置文件在Caddyfile

需注意local.867678.xyz没有真正的权威指向 这是我用来测试的

```ini
local.867678.xyz 127.0.0.1
```

这个文件夹下是由wireshark抓包的真实brave访问真实caddy的行为

客户端行为旨在模拟ArchLinux源`extra`中带的`Brave`浏览器的无痕模式

只要在公网传输的数据包与wireshark抓到的真实行为无异此项目就算成功

目前已实现ClientHello.Random与ServerHello.Random双向隐藏HMAC认证，以及认证失败时回落到sni对应的真实站点。

服务端会在同一个端口监听TCP和UDP：TCP认证失败时原样转发到sni，UDP流量则按客户端会话原样转发到sni以兼容QUIC/HTTP3探测。

SOCKS5目前支持TCP CONNECT和UDP ASSOCIATE。

客户端先建立TCP/TLS连接并在后台预热QUIC；预热完成后复用QUIC连接，每个TCP代理连接使用独立双向stream，UDP数据报也通过QUIC stream传输。

QUIC不可用时继续使用TCP/TLS。

服务端启动时会验证并缓存sni站点的真实证书链，客户端通过反向HMAC验证服务端。

TCP回退已经加入有限的早期随机填充与边界扰动（Vision-lite），之后自动切回无填充的数据流。

尚未实现Caddy本地回落、Brave指纹模拟和TLS record layer安全退出，不应用于生产环境。（我觉得他实现了这是GPT写的）

一般情况下

| 客户端                                   | 服务端                                   |
| ---------------------------------------- | ---------------------------------------- |
| 尝试用HTTP/1.1+TLS1.3+X25519MLKEM768连接 | 先返回一点虚假数据并告诉客户端我支持QUIC |
| 尝试用HTTP/3+TLS1.3+X25519MLKEM768连接   | 准备接收QUIC                             |
| QUIC建立成功                             | 交换密钥并开始传输加密数据               |

数据外表

应当看起来像是一个brave在访问Caddy（TLS）

需要做到：

```
应用 → SOCKS5 → ixa 客户端 → 首次TCP/TLS、随后QUIC（失败时保持TCP）→ ixa 服务端 → 目标网站
```

首先建立提供`h2,http/1.1`的TCP/TLS通道并校验TLS ClientHello中的HMAC，同时在后台建立`h3` QUIC。

QUIC连接会发送HTTP/3 control、SETTINGS与QPACK单向流，随后在双向stream请求中校验HMAC。

如果不是，直接返回伪装域名的内容。

失败处理

| 客户端             | 服务端                   |
| ------------------ | ------------------------ |
| 客户端尝试QUIC失败 | 退回HTTP/1.1             |
| 证书验证错误       | 立刻切断连接             |
| 迟迟没有回应       | 超时后关闭连接并重新尝试 |


## ⚠️ 安全性警告

为了配置的方便ixa协议并不像reality那样需要一个PublicKey和一个ShortId

所以key字段必须是用密码学工具生成的无关联字符

下列是一个推荐的示例用openssl生成符合要求的密码

```bash
openssl rand -hex 32
```

这里以HMAC`（RFC2104）`的规范为例
| 长度 单位：字节 | 安全性 |
| ---- | ---- |
| 16 | 刚达到不那么容易破解的临界点 |
| 32 | 现代暴力破解工具一般没辙 |
| 64 | 刚好卡在HMAC的临界点 超过就会被SHA256压缩成32字节 没意义 |

# ⚖️ 条款与授权

该项目以GNU AFFERO GENERAL PUBLIC LICENSE v3授权 详细参见LICENSE

如果您希望二次开发，也可以指定一个更高版本

如果您希望将其集成到诸如Sing-box、xray等内核中，可以修改为GPL-v3或其他

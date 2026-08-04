# ixa-go

一个简易的跨平台、强伪装、高性能代理协议实现

# 🚀 项目特点

- 抗审查
- 速度快
- 跨平台通用
- 部署简单

## 📚 项目文档

## ⚙️ 如何使用

启动服务端：

```bash
./ixa-go -c example-server.toml
```

启动客户端：

```bash
./ixa-go -c example-client.toml
curl --socks5-hostname 127.0.0.1:2080 https://example.com
```

作为systemd服务
```bash
mkdir /etc/ixa
chmod 755 /etc/ixa/*
cat <<'EOF'> /usr/lib/systemd/system/ixa-go.service
[Unit]
Description=ixa-go service
Documentation=https://867678.xyz/project/ixa-go
After=network.target nss-lookup.target network-online.target
[Service]
Type=simple
WorkingDirectory=/etc/ixa
ExecStart=/usr/bin/ixa-go server -c /etc/ixa/config.toml
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl start ixa-go
systemctl status ixa-go # 显示running即为成功
systemctl enable ixa-go # 可选 开机自启动
```

## 📄 配置文件

请直接参阅该项目的example.toml文件 里面包含了该项目所有能支持的字段

需要注意：

### ⚠️ 安全性警告

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

`sni`字段必须是一个支持TLS1.3的HTTPS URL，因为需要偷他的证书(没错这是类Reality);端口可以任意。

## 🏃 协议行为

协议行为旨在模拟`caddy-real/`下存在的wireshark抓包文件

这个文件夹下是由wireshark抓包的真实brave访问真实caddy的行为

客户端行为旨在模拟ArchLinux源`extra`中带的`Brave`浏览器的无痕模式

只要在公网传输的数据包与wireshark抓到的真实行为无异此项目就算成功

- **way-ixa.pcapng**:我前前后后用他访问了些正常的网站用于测试伪装程度
- **way-brave-caddy-baidu.pcapng**:brave访问一个反代了百度的caddy的行为 配置文件在Caddyfile

需注意local.867678.xyz没有真正的权威指向 这是我用来测试的

```ini
local.867678.xyz 127.0.0.1
```

### 🔍 详细行为

目前已实现ClientHello.Random与ServerHello.Random双向隐藏HMAC认证，以及认证失败时回落到sni对应的真实站点。

服务端会在同一个端口监听TCP和UDP：TCP认证失败时原样转发到sni，UDP流量则按客户端会话原样转发到sni以兼容QUIC/HTTP3探测。

SOCKS5目前支持TCP CONNECT和UDP ASSOCIATE。

客户端先建立TCP/TLS连接并在后台预热QUIC；预热完成后复用QUIC连接，每个TCP代理连接使用独立双向stream，UDP数据报也通过QUIC stream传输。

QUIC不可用时继续使用TCP/TLS。

服务端启动时会验证并缓存sni站点的真实证书链，客户端通过反向HMAC验证服务端。

TCP回退已经加入有限的早期随机填充与边界扰动（Vision-lite），之后自动切回无填充的数据流。

尚未实现Caddy本地回落、Brave指纹模拟和TLS record layer安全退出，不应用于生产环境。（我觉得他实现了这是GPT写的）

# ⚖️ 条款与授权

该项目以GNU AFFERO GENERAL PUBLIC LICENSE v3授权 详细参见LICENSE

如果您希望二次开发，也可以指定一个更高版本

如果您希望将其集成到诸如Sing-box、xray等内核中，可以修改为GPL-v3或其他

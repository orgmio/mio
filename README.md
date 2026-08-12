# MIO

一个简易的跨平台、强伪装、高性能代理协议实现

# 🚀 项目特点

- 抗审查
- 速度快
- 多平台通用
- 部署简单

## 📚 项目文档

## ⚙️ 如何使用

安装

```bash
cd /usr/bin
wget -O mio https://github.com/moaeiou/mio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(option)
chmod +x ./mio
cd /etc/
mkdir -p /etc/mio
touch /etc/mio/config.toml
chmod 755 /etc/mio/*
```

启动服务端：

```bash
./mio -c example-server.toml
```

启动客户端：

```bash
./mio -c example-client.toml
```

如果配置文件叫做`config.toml`那么可以直接执行二进制文件

作为systemd服务

```bash
cat <<'EOF'> /usr/lib/systemd/system/mio.service
[Unit]
Description=mio service
Documentation=https://867678.xyz/projects/mio
After=network.target nss-lookup.target network-online.target
[Service]
Type=simple
WorkingDirectory=/etc/mio
ExecStart=/usr/bin/mio server -c /etc/mio/config.toml
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl start mio
systemctl status mio # 显示running即为成功
systemctl enable mio # 可选 开机自启动
```

更新

```bash
cd /usr/bin
rm ./mio
wget -O mio https://github.com/moaeiou/mio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(Option)
chmod +x ./mio
systemctl restart mio
```

## 📄 配置文件

请直接参阅该项目的example.toml文件 里面包含了该项目所有能支持的字段

需要注意：

### ⚠️ 安全性警告

为了配置的方便mio协议并不像reality那样需要一个PublicKey和一个ShortId

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

开发使用的配置文件可以在项目根目录新建一个叫做`config.toml`的配置文件，caddy可以直接放在`caddy-real/`目录 Git已忽略他们

## 🏃 协议行为

协议行为旨在模拟`caddy-real/`下存在的wireshark抓包文件

这个文件夹下是由wireshark抓包的真实brave访问真实caddy的行为

客户端行为旨在模拟ArchLinux源`extra`中带的`Brave`浏览器的无痕模式

只要在公网传输的数据包与wireshark抓到的真实行为无异此项目就算成功

- **way-mio.pcapng**:我前前后后用他访问了些正常的网站用于测试伪装程度
- **way-brave-caddy-baidu.pcapng**:brave访问一个反代了百度的caddy的行为 配置文件在Caddyfile

需注意local.867678.xyz没有真正的权威指向 这是我用来测试的

### 🔍 详细行为

目前已实现ClientHello.Random与ServerHello.Random双向隐藏HMAC认证，以及认证失败时回落到sni对应的真实站点。

服务端会在同一个端口监听TCP和UDP：TCP认证失败时原样转发到sni，UDP流量则按客户端会话原样转发到sni以兼容QUIC/HTTP3探测。

SOCKS5目前支持TCP CONNECT和UDP ASSOCIATE。

客户端先建立TCP/TLS连接并在后台预热QUIC；预热完成后复用QUIC连接，每个TCP代理连接使用独立双向stream，UDP数据报也通过QUIC stream传输。

QUIC不可用时继续使用TCP/TLS。

服务端启动时会验证并缓存sni站点的真实证书链，客户端通过反向HMAC验证服务端。

TCP回退已经加入有限的早期随机填充与边界扰动（Vision-lite），之后自动切回无填充的数据流。

### 🤝 参考指纹和握手动作

这是真实抓包真正的客户端访问真正的服务端的抓包文件

为了做到1:1指纹这是必不可少的

brave-访问-caddy:`https://r2.867678.xyz/pcap/way-brave-caddy.pcapng`

hysteria2:`https://r2.867678.xyz/pcap/way-hysteria2.pcapng`

mio:`https://r2.867678.xyz/pcap/way-mio.pcapng`

# ⚖️ 条款与授权

该项目以GNU AFFERO GENERAL PUBLIC LICENSE v3授权 详细参见LICENSE

如果您希望二次开发，也可以指定一个更高版本

另外 本项目还有使用quic-go和utls库 前者是MIT所以可以变成AGPL-v3

后者需要附上一封版权声明 我们将他附到了LICENSE的下面

如果您希望将其集成到诸如Sing-box、xray等内核中，可以修改为GPL-v3或其他

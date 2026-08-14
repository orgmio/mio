# MIO

一个简易的跨平台、强伪装、高性能代理协议实现

# 🚀 项目特点

- 抗审查
- 速度快
- 多平台通用
- 部署简单

## 📚 项目文档

### ⚙️ 如何使用

安装（mio是通用的，也就是说他又可以是客户端又可以是服务端，具体请查看示例配置文件）

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

### ⚙ 作为systemd服务运行

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

### ⬆️ 更新

```bash
cd /usr/bin
rm ./mio
wget -O mio https://github.com/moaeiou/mio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(Option)
chmod +x ./mio
systemctl restart mio
```

### 🔩 开发

初始化环境（假设你用archlinux）

```bash
sudo pacman -Syyuu --needed git wget
git clone https://github.com/orgmio/mio.git
cd mio
wget -O mio-test https://github.com/moaeiou/mio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(Option)
chmod +x ./mio-test
cd caddy-real
wget https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz
tar -xzvf caddy_2.11.4_linux_amd64.tar.gz
rm ./caddy_2.11.4_linux_amd64.tar.gz ./LICENSE ./README.md
chmod +x ./caddy
cd ..
```

测试真brave访问真caddy（需要开好几个窗口）

需要确保你在项目根目录下且执行完毕初始化环境

```bash
sudo pacman -Syyuu --needed brave-bin wireshark-qt
echo "local.867678.xyz 127.0.0.1" >> /etc/hosts
# 启动caddy
cd caddy-real
sudo ./caddy run
# 如果是第一次跑，请打开一个新窗口下列命令
sudo ./caddy trust
# 启动brave
mkdir -p /tmp/brave-guest
brave --user-data-dir=/tmp/brave-guest
# 启动wireshark抓包
sudo wireshark
# 过滤目标
tls.handshake.extensions_server_name == "local.867678.xyz"
# 访问 local.867678.xyz即可
```

测试mio协议

在客户端 mio项目根目录上：

```bash
touch config.toml
# 在config.toml中写入你的客户端配置文件
go run .
```

在服务端：

```bash
touch config.toml
wget -O mio https://github.com/moaeiou/mio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(Option)
chmod +x ./mio
./mio
```

抓包和过滤目标的方法与brave中的示例相同

## ⚠️ 安全性警告

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

服务端会在同一个端口监听TCP和UDP：TCP认证失败时原样转发到sni，UDP流量则按客户端会话原样转发到sni以兼容QUIC/HTTP3探测。

客户端先建立TCP/TLS连接并在后台预热QUIC；预热完成后复用QUIC连接，每个TCP代理连接使用独立双向stream，UDP数据报也通过QUIC stream传输。

QUIC不可用时继续使用TCP/TLS。

服务端启动时会验证并缓存sni站点的真实证书链，客户端通过反向HMAC验证服务端。

TCP回退已经加入有限的早期随机填充与边界扰动（XTLS-vision-like），之后自动切回无填充的数据流。

### 🤝 参考指纹和握手动作

这是真实抓包真正的客户端访问真正的服务端的抓包文件

为了做到1:1指纹这是必不可少的

brave访问caddy反代的百度:`https://r2.867678.xyz/pcap/way-brave-caddy-baidu.pcapng`

mio:`https://r2.867678.xyz/pcap/way-mio.pcapng`

# ⚖️ 条款与授权

该项目以GNU AFFERO GENERAL PUBLIC LICENSE v3授权 详细参见LICENSE

如果您希望二次开发，也可以指定一个更高版本

另外 本项目还有魔改quic-go和utls库（已迁移到github.com/orgmio/quic-mio与github.com/orgmio/utls-mio）

前者是MIT所以可以变成AGPL-v3 后者需要附上一封版权声明 我们将他附到了LICENSE的下面

如果您希望将其集成到诸如xray等代理工具中，可以修改为GPL-v3或其他

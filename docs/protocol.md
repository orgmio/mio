# mio 协议规范

本文描述 mio 的线上格式，目的是让其他实现不看代码也能互通。
Go 代码可以直接引用 `github.com/orgmio/mio/protocol`，见文末。

## 0. 版本

mio 没有单独的协议版本号，**mio 的版本号（`protocol.Version`，例如 `0.5.0`）就是协议版本**，下文记作 `VERSION`。
它参与 TCP 认证密钥、QUIC 标记和 QUIC 认证证明的计算。版本号不同的两端在线上的表现与公钥填错完全相同：服务端把连接当作普通访问交给伪装站，客户端等不到响应。
所以**升级时客户端和服务端必须一起升级**，哪怕只是补丁版本。

## 0.1 密钥

服务端持有一对 X25519 静态密钥，由 `mio keygen` 生成：

- **私钥** `S`：只放在服务端（`[inbounds].private_key`）。
- **公钥** `S_pub`：放在客户端（`[outbounds].public_key`）。客户端靠它确认对端确实是这台服务端；服务端则把「知道 `S_pub`」视为客户端获得了授权。

两者都编码为不带填充的 URL 安全 base64（43 个字符）。mio 不使用密码：所有认证用的密钥都来自 X25519 共享密钥，其中没有任何低熵的值可供离线猜测；没有 `S`，也无法冒充服务端。

记号：`‖` 表示字节拼接；多字节整数一律大端；`HKDF` 指 HKDF-SHA256；`AEAD` 指 AES-256-GCM（12 字节 nonce，16 字节 tag）。

## 1. 总览

mio 有两条传输路径，监听同一个端口：

- **TCP 路径**：外观是一条到伪装站（`dest`）的普通 TLS 连接，认证后数据由 mio 自己的记录层加密。
- **QUIC 路径**：外观是到伪装站的 HTTP/3，认证靠 ClientHello.random 里的标记和握手后基于 `S` 的双向证明，数据由 QUIC 本身加密。

两条路径在认证之后使用相同的[目标请求](#4-目标请求)格式。

## 2. TCP 路径

### 2.1 借用伪装站完成 TLS 握手

1. 客户端用 Chrome 指纹（uTLS）向服务端发起 TLS 握手，SNI 为 `dest`。
2. 服务端为每个入站连接拨号 `dest:dest_port`，按 TLS 记录双向原样转发，同时记下：
   - `client_random`：ClientHello 的 random（32 字节）。
   - `E_pub`：ClientHello 里 `key_share` 扩展中 X25519（group `0x001d`）的份额（32 字节）。
   - `server_random`：最后一条 ServerHello 的 random（出现 HelloRetryRequest 时以最后一条为准）。
3. 客户端与真实的伪装站完成整个 TLS 握手，并按正常规则校验其证书。

### 2.2 认证记录

客户端在发出 ClientHello 之前就持有 `E_pub` 对应的私钥 `E`，两端可以算出同一个共享密钥：

```
shared = X25519(E, S_pub) = X25519(S, E_pub)
```

`E_pub` 本来就是 ClientHello 里的普通 key_share，所以这一步不会在线上多出任何字节。

握手完成后，客户端直接在 TCP 上发出一条认证记录：

```
key       = HKDF(ikm = shared, salt = client_random ‖ server_random, info = "mio auth " ‖ VERSION, 32)
plaintext = client_share(1216) ‖ random_padding(32–1024)
header    = 17 03 03 ‖ length(2)            ; length = len(plaintext) + 16
record    = header ‖ AEAD-Seal(key, nonce = 0^12, plaintext, ad = header)
```

- `client_share` = X25519 公钥（32）‖ ML-KEM-768 封装公钥（1184）。

服务端在看到 ServerHello 之后，用 `S` 和 `E_pub` 算出 `shared`，对客户端发来的每一条 Application Data 记录尝试用上面的方式解密。解密成功且明文长度在 `1216+32` 到 `1216+1024` 之间即认证通过。
认证通过后，服务端吞掉这条记录，停止转发并关闭到 `dest` 的连接；否则继续转发，对方看到的始终是伪装站。

因为密钥依赖每条连接都不同的 `server_random`，所以录下的认证记录无法在别的连接上重放。
不知道 `S_pub` 的人算不出 `shared`，造不出认证记录；被动监听者也无从离线猜测，因为没有任何低熵的秘密。

### 2.3 密钥交换与会话密钥

两个方向的密钥由下面的函数派生（代码中为 `protocol.DeriveKeys`）：

```
DeriveKeys(secret):
  ikm  = secret ‖ shared
  salt = client_random ‖ server_random
  c2s  = HKDF(ikm, salt, "mio c2s", 32)      ; 客户端 → 服务端
  s2c  = HKDF(ikm, salt, "mio s2c", 32)      ; 服务端 → 客户端
```

1. 服务端生成 X25519 临时密钥，对 ML-KEM-768 封装公钥做封装，得到：
   - `server_share` = X25519 公钥（32）‖ ML-KEM-768 密文（1088）
   - `secret` = X25519 共享密钥（32）‖ ML-KEM 共享密钥（32）
2. 服务端用 `DeriveKeys(空)` 的 `s2c` 密钥，以序号 0 发出一条 **ready 帧**，负载为 `server_share`。
3. 客户端在收到 ready 帧之前，会跳过所有解不开的记录（例如伪装站在握手后发来的 NewSessionTicket）。收到 ready 后算出同样的 `secret`。
   能发出可解密的 ready 帧，就证明对端算得出 `shared`，也就是持有 `S`，因此中间人无法冒充服务端。
4. 双方都切换到 `DeriveKeys(secret)`，两个方向的序号都重置为 0。此后所有记录都使用会话密钥。

### 2.4 记录层与帧

每个帧单独封装成一条 TLS Application Data 记录：

```
header = 17 03 03 ‖ length(2)
record = header ‖ AEAD-Seal(key, nonce(seq), frame, ad = header)
nonce(seq) = 0^4 ‖ seq(8)          ; seq 每个方向独立，从 0 开始，每条记录加 1
```

记录体（密文）最长 16640 字节。解密后的帧为：

```
frame = type(1) ‖ payload_length(2) ‖ payload ‖ padding
```

| type | 名称  | 含义 |
|------|-------|------|
| 0    | ready | 服务端就绪，负载为 `server_share` |
| 1    | data  | 应用数据，负载最长 16383 字节 |
| 2    | close | 本方向不再发送数据（半关闭），负载为空 |

- `padding` 是随机字节，接收方按 `payload_length` 取负载后直接丢弃剩余部分。
- **接收方遇到不认识的 type 必须跳过该帧**，以便以后扩展。

默认填充策略（`protocol.DefaultPadding`）：

- ready 帧：0–1024 字节。
- 前 8 个 data 帧：负载不足 900 字节的，补到整帧 900–1400 字节；其余随机加 0–255 字节。
- 之后的帧不填充。
- 例外：目标请求和应答所在的 data 帧，填充 16–512 字节。

发送方会尽量让内层的一个 TLS 记录对应一个帧。如果缓冲里留着不完整的内层记录，最多等 50ms 就会把它发出。这只影响分帧方式，不影响格式。

## 3. QUIC 路径

### 3.1 标记

客户端把 ClientHello.random 设为：

```
nonce  = 随机 16 字节
minute = floor(unix_time / 60)，8 字节
marker_key = HKDF(ikm = S_pub, salt = 空, info = "mio quic marker " ‖ VERSION, 32)
random     = nonce ‖ HMAC-SHA256(marker_key, nonce ‖ minute)[:16]
```

服务端用 RFC 9001 的方法解开客户端的 Initial 包，取出 random，接受 `minute` 与本地相差 ±1 的标记。用过的 nonce 会被记住 5 分钟，重复的视为重放。
没有有效标记的 UDP 流量会原样转发给伪装站。**双方时钟误差需要在 1 分钟以内。**

### 3.2 握手与认证

服务端使用临时自签证书，ALPN 为 `h3`，TLS 1.3；客户端不校验这个证书，对端身份由下面的证明确认。

```
exporter = TLS-Exporter("mio quic auth", 空, 32)          ; 双方各自导出，绑定到这条 QUIC 连接
C        = 客户端新生成的 X25519 临时密钥
shared   = X25519(C, S_pub) = X25519(S, C_pub)
key      = HKDF(ikm = shared, salt = exporter, info = "mio quic auth " ‖ VERSION, 32)
```

1. 客户端打开第一个 stream，发送 `C_pub(32) ‖ HMAC-SHA256(key, "client")`，共 64 字节。
2. 服务端算出 `key` 并校验客户端证明，通过后回复 `HMAC-SHA256(key, "server")`（32 字节），然后关闭这个 stream。
3. 客户端校验服务端的回复，通过后才开始发送代理请求。整个过程须在 5 秒内完成。

只有持有 `S` 的一方能算出服务端的回复，所以即使客户端不校验证书，中间人也无法冒充服务端。

### 3.3 数据

之后客户端每发起一个代理连接就打开一个新的双向 stream，先交换[目标请求](#4-目标请求)，再直接传输原始字节。QUIC 本身已经加密，所以这里不再套用第 2.4 节的帧格式。

## 4. 目标请求

认证后的第一段数据是客户端发出的目标地址：

```
request = atyp(1) ‖ address ‖ port(2)
  atyp 1：address = IPv4（4 字节）
  atyp 3：address = length(1) ‖ 域名（1–255 字节）
  atyp 4：address = IPv6（16 字节）
```

服务端连接目标后回复 1 字节：`0` 表示成功，`1` 表示失败。成功之后双向转发数据。
在 TCP 路径上，请求和应答各自放在一个 data 帧里；在 QUIC 路径上，直接写在 stream 上。

## 5. 在 Go 中引用

```go
import "github.com/orgmio/mio/protocol"
```

| 接口 | 作用 |
|------|------|
| `DialTCP(ctx, Peer, target)` | 完整的客户端 TCP 路径，返回已加密、已连上目标的连接 |
| `Handshake(ctx, conn, Peer)` | 只做客户端握手（2.1–2.3），返回 `*Conn` |
| `VerifyAuth` / `Accept` | 服务端认证与握手 |
| `GenerateKeyPair` / `ParsePrivateKey` / `ParsePublicKey` | 0.1 节的密钥生成与解析 |
| `Conn` / `NewConn` | 2.4 节的记录层，可配合自己的握手使用 |
| `DeriveKeys` | 2.3 节的密钥派生 |
| `PaddingPolicy` / `DefaultPadding` | 填充策略，可通过 `Conn.SetPaddingPolicy` 替换 |
| `WriteRequest` / `ReadRequest` / `WriteReply` / `ReadReply` | 第 4 节的请求格式 |
| `protocol/quicauth` | 第 3 节的标记、重放缓存与认证（`ClientAuth` / `ServerAuth`） |
| `Version` | 第 0 节的版本号，引用方必须与对端完全一致 |

`protocol` 及其子包不依赖 quic-go。只有引用 `client`、`server` 包时才需要 quic-go，而且这时需要在自己的 `go.mod` 里加上与 mio 相同的 `replace`：

```
replace github.com/apernet/quic-go => github.com/HyNetworks/quic-go v0.65.1-0.20261109005002-2895f039137a
```

这是因为 Go 只认主模块里的 `replace`，依赖里写的 `replace` 不会生效。

# mio怎么建立连接

这篇文档用简单的话说明：应用程序连到本地 SOCKS5 后，mio 怎么在 TCP 和 QUIC 之间选择，以及其中的数据怎么走。

## 先看一张图

<svg xmlns="http://www.w3.org/2000/svg" width="900" height="430" viewBox="0 0 900 430" role="img" aria-labelledby="title desc">
  <title id="title">mio连接选择示意图</title>
  <desc id="desc">本地应用通过SOCKS5把请求交给mio客户端，客户端在探测时并行建立TCP和QUIC连接，选择一条交给应用；之后定期重新比较。</desc>
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L0,6 L9,3 z" fill="#334155"/>
    </marker>
    <style>
      .box { fill: #f8fafc; stroke: #334155; stroke-width: 2; rx: 10; }
      .probe { fill: #ecfeff; stroke: #0e7490; stroke-width: 2; rx: 10; }
      .text { font: 16px sans-serif; fill: #0f172a; text-anchor: middle; }
      .small { font: 13px sans-serif; fill: #334155; text-anchor: middle; }
      .line { stroke: #334155; stroke-width: 2; fill: none; marker-end: url(#arrow); }
      .race { stroke: #0e7490; stroke-width: 2; fill: none; marker-end: url(#arrow); }
    </style>
  </defs>
  <rect class="box" x="30" y="160" width="155" height="70"/>
  <text class="text" x="107" y="190">应用程序</text>
  <text class="small" x="107" y="213">发起 SOCKS5 CONNECT</text>

  <rect class="box" x="250" y="160" width="175" height="70"/>
  <text class="text" x="337" y="190">mio 客户端</text>
  <text class="small" x="337" y="213">选择 TCP 或 QUIC</text>
  <path class="line" d="M185 195 H245"/>

  <rect class="probe" x="505" y="55" width="170" height="70"/>
  <text class="text" x="590" y="85">TCP 代理连接</text>
  <text class="small" x="590" y="108">握手、认证、连接目标</text>

  <rect class="probe" x="505" y="265" width="170" height="70"/>
  <text class="text" x="590" y="295">QUIC stream</text>
  <text class="small" x="590" y="318">会话认证、连接目标</text>

  <rect class="box" x="730" y="160" width="145" height="70"/>
  <text class="text" x="802" y="190">目标网站</text>
  <text class="small" x="802" y="213">只使用获选连接</text>

  <path class="race" d="M425 178 C455 150 468 100 500 95"/>
  <path class="race" d="M425 212 C455 240 468 290 500 295"/>
  <path class="line" d="M675 90 C710 105 712 158 725 177"/>
  <path class="line" d="M675 300 C710 285 712 232 725 213"/>

  <text class="small" x="590" y="385">首次与周期探测：两路同时尝试，先成功的连接先返回</text>
  <text class="small" x="590" y="407">另一条随后关闭；不复制或重发应用数据</text>
</svg>

## 第一次连接

应用程序通过本地 SOCKS5 发起 TCP `CONNECT`。mio 会同时试两条路：

- **TCP 路**：连接 mio 服务端，经 uTLS 与伪装站握手；发送认证信息，服务端通过认证后接管连接；然后连接目标网站。
- **QUIC 路**：连接 mio 服务端的 UDP 端口，完成 QUIC 和 mio 会话认证；再通过一个 QUIC stream 请求服务端连接同一个目标网站。

哪条路先把代理连接建好、收到目标连接成功的应答，mio 就先把那条连接交给应用。另一条路即使后来成功，也会关闭。

应用的数据只通过交给应用的那一条连接发送，不会同时复制到 TCP 和 QUIC。探测期间，两条路可能各自让服务端尝试连接同一个目标；输家会很快关闭，因此目标端可能看到一次额外的短连接。

如果两条路都失败，这次请求返回连接错误，mio 暂时把 TCP 作为默认选择，之后再试。

## 后续连接

mio 记录 TCP 和 QUIC 建立代理连接所用的时间，并用平滑平均比较它们。简单说，新测量不会立刻完全覆盖旧结果：旧结果占大约四分之三，新结果占大约四分之一。两路都可用时，平均更快的那条会成为后续请求的优先线路。

如果优先线路发生传输层错误，mio 会尝试另一条线路；如果是目标明确拒绝连接，错误会直接返回，不会把它误当成线路故障。

mio 会在每次探测后随机等待约 10 到 30 分钟，再用新的目标请求比较一次。网络状况变了，优先线路也可以随之切换。

## 计时包括什么

这里测的不是单个 UDP 包或 TCP 包谁先到，而是**整个代理请求建立成功需要多久**：

- TCP 包含 TCP 建连、TLS 握手、认证、目标连接和成功应答。
- QUIC 包含 UDP/QUIC 建连、会话认证、stream 请求、目标连接和成功应答。

因此，测出来的是从应用请求到代理连接可用的整体速度，不是纯粹的网络 RTT。

## TLS 数据怎么处理

TCP 代理连接进入数据阶段后，mio 会先用自己的 AEAD 保护目标 TLS 的 ClientHello 和 ServerHello 等握手 record。双方确认 TLS 握手开始后，目标 TLS 已加密的 Application Data record 会按原字节透传，不再套一层 mio AEAD；普通非 TLS 数据仍使用 mio AEAD。

前几个方向性数据 record 会额外伴随随机长度的 mio 填充 record。它们由对端识别并丢弃，不会转发给目标网站。目标 TLS record 自身的长度不能随意改写，否则会破坏 TLS；因此这类填充只能改变附近的流量形态，不能保证每个包都与真实 TLS 握手等长，也不能保证完全消除 TLS-in-TLS 特征。

## UDP 限制

mio 的 SOCKS5 只允许 TCP `CONNECT`，不提供应用 UDP 隧道，所以浏览器不能通过 SOCKS5 把 HTTP/3 的 UDP/443 流量塞进 mio。mio 客户端与服务端之间使用的 QUIC/UDP 是 mio 自己的传输连接，不是应用的 UDP 数据。

这项限制只约束经过本地 SOCKS5 的流量；它不会阻止设备上其他程序绕过 SOCKS5，直接向互联网发送 UDP/443。

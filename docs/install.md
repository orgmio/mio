# 安装mio

此章节讲解如何安装mio。

## 下载二进制文件

mio基于Go语言编写，所以产物是一个二进制文件。
一般来讲只要下载到了正确的二进制文件就可以直接运行。
[在这里下载](https://github.com/orgmio/mio/releases)
当然如果你嫌微软破CDN速度太慢，我们也有官方镜像站。
转到[这里](https://867678.xyz/docs/mirrors)获取有关镜像站的详细信息。

文件名规则：
`mio-OS名-指令集和特性加速-使用的libc`
比如：
`mio-linux-amd64v4-glibc`
意思是 对于Linux系统，AMD64指令集的CPU，使用V4优化（也就是AVX-512），和GNU LibC。

当然，对于arm指令集的系统，因为github actions的ubuntu-latest-arm半天开不出来机器，所以这里只能编译为静态文件，也就是后面没有-libc名。

对于我们不支持的指令集，您也可以克隆代码并手动运行`go build`，或提交issue并邮寄机器以供我们测试。

### 对于包管理器

一般来讲很多软件都会封装成.deb或.rpm等格式方便包管理器使用。
但是mio现在和将来都不会如此，更不会提交到任何Linux发行版的软件仓库中。
这是因为对于一款网络插件，能用和安全是第一性原则。
而现有的任何包管理器几乎都有滞后性，mio为了最大限度的让客户接收最新更新，
不得不做出取舍不兼容任何包管理器，但是后续我们会出一款及时性的包管理器，
可能会用mio作为传输层，敬请期待。

## 作为服务运行

相信在座的你肯定不希望每次重启机器后重启作为实时进程的mio吧，
所以mio提供了一些官方的方式让您方便的将其作为守护进程。

### 对于systemd系统

首先要创建一个叫做mio的用户和把`/etc/mio`目录交给这个用户。
```bash
mkdir -p /etc/mio/
useradd -rs /sbin/nologin mio
chown -R mio:mio /etc/mio/
```

下面的内容应该出现在`/usr/lib/systemd/system/mio.service`文件中。

```
[Unit]
Description=mio service
Documentation=https://github.com/orgmio/mio/tree/main/docs
After=network.target nss-lookup.target network-online.target

[Service]
CPUSchedulingPolicy=rr
CPUSchedulingPriority=99
User=mio
StateDirectory=mio
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/bin/mio run -c /etc/mio/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
```

这段systemd文件会启动一个位于`/usr/bin/mio`的二进制文件，并附带参数`run -c /etc/mio/config.toml`。

同时不要在配置文件的`[log]`中写`output`字段，直接要日志输出给systemd是最好的解决方式。

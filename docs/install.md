# 安装mio

此章节讲解如何安装mio。

## 下载二进制文件

mio基于Go语言编写，所以产物是一个二进制文件。
一般来讲只要下载到了正确的二进制文件就可以直接运行。
[在这里下载](https://github.com/orgmio/mio/releases)。

文件名规则：
`mio-OS名-指令集和特性加速-使用的libc`
比如：
`mio-linux-amd64v4-glibc`

意思是 对于Linux系统，AMD64指令集的CPU，使用V4优化（也就是AVX-512），和GNU LibC。

LibC的话虽然mio不包含任何C语言代码，但是DNS解析部分仍旧需要使用宿主机的DNS模块，所以选择正确的C语言库可以提升性能。

当然，对于arm指令集的平台，因为github actions的ubuntu-latest-arm半天开不出来机器，所以这里只能编译为静态文件，也就是后面没有-libc名。

对于我们不支持的指令集，您也可以克隆代码并手动运行`go build`，或提交issue并邮寄机器以供我们测试。

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

### 对于 SysV init 系统

以下示例适用于使用 SysV init、Debian 版 `start-stop-daemon` 和 `update-rc.d` 的系统。
先将 mio 安装到 `/usr/bin/mio`，然后以 root 身份创建服务账户并安装配置文件。

```sh
id -u mio >/dev/null 2>&1 || useradd --system --user-group --shell /usr/sbin/nologin mio
install -d -o root -g mio -m 0750 /etc/mio
install -o root -g mio -m 0640 ./config.toml /etc/mio/config.toml
```

如果 mio 需要监听 443 等低于 1024 的端口，且系统要求绑定这些端口的进程具有特权，
执行 `setcap cap_net_bind_service=+ep /usr/bin/mio`。替换二进制后需要重新设置。

将以下脚本保存为 `/etc/init.d/mio`。

```sh
#!/bin/sh
### BEGIN INIT INFO
# Provides:          mio
# Required-Start:    $remote_fs $network
# Required-Stop:     $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: mio proxy service
### END INIT INFO

PATH=/usr/sbin:/usr/bin:/sbin:/bin
DAEMON=/usr/bin/mio
CONFIG=/etc/mio/config.toml
PIDFILE=/run/mio.pid
LOGFILE=/var/log/mio.log
RUN_AS=mio

status() {
    start-stop-daemon --status --pidfile "$PIDFILE" \
        --exec "$DAEMON" --user "$RUN_AS"
}

start() {
    if [ ! -x "$DAEMON" ] || [ ! -r "$CONFIG" ]; then
        printf 'Check executable %s and configuration %s.\n' "$DAEMON" "$CONFIG" >&2
        return 1
    fi

    umask 027
    start-stop-daemon --start --quiet --oknodo --background --make-pidfile \
        --pidfile "$PIDFILE" --exec "$DAEMON" --user "$RUN_AS" \
        --chuid "$RUN_AS" --no-close -- run -c "$CONFIG" \
        </dev/null >>"$LOGFILE" 2>&1 || return $?

    sleep 1
    if ! status; then
        printf 'mio failed to start. See %s.\n' "$LOGFILE" >&2
        return 1
    fi
}

stop() {
    start-stop-daemon --stop --quiet --oknodo --retry TERM/10/KILL/5 \
        --pidfile "$PIDFILE" --exec "$DAEMON" --user "$RUN_AS" --remove-pidfile
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    restart|force-reload) stop && start ;;
    status)
        status
        result=$?
        case "$result" in
            0) printf 'mio is running.\n' ;;
            1|3) printf 'mio is not running.\n' ;;
        esac
        exit "$result"
        ;;
    *)
        printf 'Usage: %s {start|stop|restart|force-reload|status}\n' "$0" >&2
        exit 2
        ;;
esac
```

赋予脚本执行权限、注册开机启动并启动服务。

```sh
chmod 0755 /etc/init.d/mio
update-rc.d mio defaults
/etc/init.d/mio start
/etc/init.d/mio status
```

修改配置后运行 `/etc/init.d/mio restart`。省略配置中 `[log]` 的 `output` 时，
服务日志写入 `/var/log/mio.log`。

参考手册：[start-stop-daemon](https://manpages.debian.org/bookworm/dpkg/start-stop-daemon.8.en.html) 和
[update-rc.d](https://manpages.debian.org/bookworm/init-system-helpers/update-rc.d.8.en.html)。

### 对于 OpenWrt

将适合路由器 CPU 架构的 Linux 静态二进制安装到 `/usr/bin/mio`，并将配置放到
`/etc/mio/config.toml`。以下示例由 OpenWrt 的 `procd` 以 root 身份运行 mio，
配置文件可设为仅 root 可读写。

```sh
chmod 0755 /usr/bin/mio
chmod 0600 /etc/mio/config.toml
```

将以下脚本保存为 `/etc/init.d/mio`。

```sh
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=10

DAEMON=/usr/bin/mio
CONFIG=/etc/mio/config.toml

start_service() {
    if [ ! -x "$DAEMON" ] || [ ! -r "$CONFIG" ]; then
        printf 'Check executable %s and configuration %s.\n' "$DAEMON" "$CONFIG" >&2
        return 1
    fi

    procd_open_instance
    procd_set_param command "$DAEMON" run -c "$CONFIG"
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

赋予脚本执行权限、启用开机启动并立即启动 mio。

```sh
chmod 0755 /etc/init.d/mio
/etc/init.d/mio enable
/etc/init.d/mio start
/etc/init.d/mio status
```

修改配置后运行 `/etc/init.d/mio restart`。省略配置中 `[log]` 的 `output` 时，
可以用 `logread -e mio` 查看服务日志。
有关进程管理选项，参见 [OpenWrt procd 文档](https://openwrt.org/docs/guide-developer/procd-init-scripts)。

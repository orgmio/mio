package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/orgmio/mio/protocol"
)

// proxy 读取客户端的目标地址请求，连上目标后双向转发，结束时关闭 conn。
func (s *Server) proxy(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	from := conn.RemoteAddr().String()

	conn.SetReadDeadline(time.Now().Add(requestTimeout))
	target, err := protocol.ReadRequest(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		slog.Warn("read request failed", "from", from, "err", err)
		return
	}

	dialer := net.Dialer{Timeout: dialTimeout}
	remote, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		slog.Warn("dial target failed", "from", from, "target", target, "err", err)
		if p, ok := conn.(interface{ SetNextPadding(int, int) }); ok {
			p.SetNextPadding(16, 512)
		}
		protocol.WriteReply(conn, false)
		return
	}
	defer remote.Close()

	if p, ok := conn.(interface{ SetNextPadding(int, int) }); ok {
		p.SetNextPadding(16, 512)
	}
	if err := protocol.WriteReply(conn, true); err != nil {
		return
	}
	slog.Info("proxy", "from", from, "target", target)
	pipe(conn, remote)
}

// pipe 双向拷贝；一侧正常结束时只半关闭对端，出错则两端都关闭。
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			dst.Close()
			src.Close()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	wg.Add(2)
	go copyHalf(a, b)
	go copyHalf(b, a)
	wg.Wait()
}

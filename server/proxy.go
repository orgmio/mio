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
	request, err := protocol.ReadStreamRequest(conn)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		slog.Error("inbound/mio: process connection from "+from+": read request", "err", err)
		return
	}
	if p, ok := conn.(interface{ SetNextPadding(int, int) }); ok {
		p.SetNextPadding(16, 512)
	}
	if request.ProbeEarlyTCP {
		protocol.WriteReply(conn, true)
		return
	}
	if request.UDPAssociate {
		if err := protocol.WriteReply(conn, true); err == nil {
			relayUDPAssociation(ctx, conn)
		}
		return
	}
	target := request.Target

	slog.Info("inbound/mio: inbound connection from " + from)
	slog.Info("inbound/mio: inbound connection to " + target)
	dialer := net.Dialer{Timeout: dialTimeout}
	remote, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		slog.Error("outbound/direct: open connection to "+target, "err", err)
		protocol.WriteReply(conn, false)
		return
	}
	defer remote.Close()

	if err := protocol.WriteReply(conn, true); err != nil {
		return
	}
	slog.Info("outbound/direct: outbound connection to " + target)
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

package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/orgmio/mio/config"
	"github.com/things-go/go-socks5"
)

type slogLogger struct{}

func (slogLogger) Errorf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
}

type SOCKS5Node struct {
	config config.SOCKS5
	server *socks5.Server
}

func NewSOCKS5(cfg config.SOCKS5) *SOCKS5Node {
	server := socks5.NewServer(
		socks5.WithLogger(slogLogger{}),
		socks5.WithDialAndRequest(dialWithLog),
	)
	return &SOCKS5Node{config: cfg, server: server}
}

func dialWithLog(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		slog.Warn("dial failed", "dest", addr, "err", err)
		return nil, err
	}
	slog.Debug("dial succeeded", "dest", addr)
	return &sniConn{
		Conn: conn,
		from: request.RemoteAddr.String(),
		dest: addr,
		host: request.RawDestAddr.FQDN,
	}, nil
}

type loggingListener struct{ net.Listener }

func (l loggingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		slog.Info("accepted tcp connection", "from", conn.RemoteAddr().String())
	}
	return conn, err
}

func (node *SOCKS5Node) Run(ctx context.Context) error {
	address := net.JoinHostPort(node.config.Listen, strconv.Itoa(node.config.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}

	slog.Info("Listen Socks5 successfully at ", "address", listener.Addr().String())
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	if err := node.server.Serve(loggingListener{listener}); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

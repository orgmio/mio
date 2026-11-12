package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/protocol"
	"github.com/things-go/go-socks5"
)

type slogLogger struct{}

func (slogLogger) Errorf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
}

// noResolver 不在本地解析域名，域名原样交给服务端解析。
type noResolver struct{}

func (noResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

type SOCKS5Node struct {
	config config.Outbound
	dialer *Dialer
	server *socks5.Server
}

func NewSOCKS5(cfg config.Outbound) (*SOCKS5Node, error) {
	publicKey, err := protocol.ParsePublicKey(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	node := &SOCKS5Node{config: cfg, dialer: NewDialer(protocol.Peer{
		Server:     cfg.Server,
		ServerPort: cfg.ServerPort,
		Dest:       cfg.Dest,
		PublicKey:  publicKey,
	})}
	node.server = socks5.NewServer(
		socks5.WithLogger(slogLogger{}),
		socks5.WithResolver(noResolver{}),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true}),
		socks5.WithDialAndRequest(node.dial),
	)
	return node, nil
}

func (node *SOCKS5Node) dial(ctx context.Context, _, _ string, request *socks5.Request) (net.Conn, error) {
	dest := request.RawDestAddr
	host := dest.FQDN
	if host == "" {
		host = dest.IP.String()
	}
	target := net.JoinHostPort(host, strconv.Itoa(dest.Port))

	conn, err := node.dialer.Dial(ctx, target)
	if err != nil {
		slog.Warn("dial failed", "dest", target, "err", err)
		return nil, err
	}
	slog.Debug("dial succeeded", "dest", target)
	return &Sniff{
		Conn: conn,
		from: request.RemoteAddr.String(),
		dest: target,
		host: dest.FQDN,
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
	address := net.JoinHostPort(node.config.SocksListen, strconv.Itoa(node.config.SocksListenPort))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	slog.Info("Listen Socks5 successfully at ", "address", listener.Addr().String())
	go node.dialer.WarmUp(ctx)
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	if err := node.server.Serve(loggingListener{listener}); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

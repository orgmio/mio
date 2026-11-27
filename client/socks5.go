package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/protocol"
	"github.com/things-go/go-socks5"
)

type slogLogger struct{}

func (slogLogger) Errorf(format string, args ...any) {
	slog.Error("inbound/socks: " + fmt.Sprintf(format, args...))
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

	listener net.Listener
}

func NewSOCKS5(cfg config.Outbound) (*SOCKS5Node, error) {
	publicKey, err := protocol.ParsePublicKey(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	node := &SOCKS5Node{config: cfg, dialer: newDialer(protocol.Peer{
		Server:     cfg.Server,
		ServerPort: cfg.ServerPort,
		Dest:       cfg.Dest,
		PublicKey:  publicKey,
	}, cfg.Transport)}
	node.server = socks5.NewServer(
		socks5.WithLogger(slogLogger{}),
		socks5.WithResolver(noResolver{}),
		socks5.WithRule(&socks5.PermitCommand{EnableConnect: true, EnableAssociate: cfg.Socks5UDP}),
		socks5.WithDialAndRequest(node.dial),
		socks5.WithAssociateHandle(node.associateUDP),
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

	slog.Info("inbound/socks: inbound connection to " + target)
	conn, err := node.dialer.Dial(ctx, target)
	if err != nil {
		slog.Error("outbound/mio: open connection to "+target, "err", err)
		return nil, err
	}
	slog.Info("outbound/mio: outbound connection to " + target)
	return &sniLogConn{Conn: conn, host: dest.FQDN}, nil
}

// Run 开始监听并处理 SOCKS5 连接，直到 ctx 结束。等同于先 Start 再 Serve。
func (node *SOCKS5Node) Run(ctx context.Context) error {
	if err := node.Start(ctx); err != nil {
		return err
	}
	return node.Serve(ctx)
}

// Start 开始监听本地 SOCKS5 端口。
func (node *SOCKS5Node) Start(context.Context) error {
	address := net.JoinHostPort(node.config.SocksListen, strconv.Itoa(node.config.SocksListenPort))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	node.listener = listener
	slog.Info("inbound/socks: tcp server started at " + listener.Addr().String())
	return nil
}

// Close 释放监听端口并关闭出站拨号器。
func (node *SOCKS5Node) Close() {
	if node.listener != nil {
		node.listener.Close()
	}
	node.dialer.Close()
}

// Serve 处理 Start 之后到来的 SOCKS5 连接，直到 ctx 结束。必须先调用 Start。
func (node *SOCKS5Node) Serve(ctx context.Context) error {
	listener := node.listener
	if listener == nil {
		return errors.New("socks5 node is not started")
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	defer node.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		slog.Info("inbound/socks: inbound connection from " + conn.RemoteAddr().String())
		workers.Go(func() {
			stop := context.AfterFunc(node.dialer.ctx, func() { conn.Close() })
			defer stop()
			if err := node.server.ServeConn(conn); err != nil && node.dialer.ctx.Err() == nil {
				slog.Error("inbound/socks: server: " + err.Error())
			}
		})
	}
}

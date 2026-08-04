package protocal

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	socks5 "github.com/things-go/go-socks5"
)

type SOCKS5Config struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
}

func (c SOCKS5Config) Address() string {
	return net.JoinHostPort(c.Listen, strconv.Itoa(c.Port))
}

type SOCKS5Server struct {
	config SOCKS5Config
	server *socks5.Server
}

func NewSOCKS5ServerWithTransport(config SOCKS5Config, dialContext func(context.Context, string, string) (net.Conn, error)) *SOCKS5Server {
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.Default())),
		socks5.WithResolver(remoteResolver{}),
		socks5.WithDial(dialContext),
	)
	return &SOCKS5Server{config: config, server: server}
}

func (s *SOCKS5Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.Address())
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	err = s.server.Serve(listener)
	if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

type remoteResolver struct{}

func (remoteResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

func relay(a, b net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyOneWay := func(destination, source net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(destination, source)
		if halfCloser, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
		} else {
			_ = destination.Close()
		}
	}
	go copyOneWay(a, b)
	go copyOneWay(b, a)
	wait.Wait()
}

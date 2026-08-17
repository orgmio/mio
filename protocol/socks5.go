package mio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
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

func NewSOCKS5Server(config SOCKS5Config, dialContext func(context.Context, string, string) (net.Conn, error)) *SOCKS5Server {
	server := socks5.NewServer(
		socks5.WithLogger(quietSOCKSLogger{}),
		socks5.WithResolver(remoteResolver{}),
		socks5.WithDial(dialContext),
		socks5.WithBufferPool(bufferpool.NewPool(relayBufferSize)),
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

type quietSOCKSLogger struct{}

func (quietSOCKSLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if isBenignProxyError(msg) {
		return
	}
	log.Print(msg)
}

func isBenignProxyError(msg string) bool {
	switch {
	case strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "use of closed network connection"),
		strings.Contains(msg, io.EOF.Error()),
		strings.Contains(msg, io.ErrClosedPipe.Error()):
		return true
	default:
		return false
	}
}

type remoteResolver struct{}

func (remoteResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

const relayBufferSize = 256 * 1024

var relayBuffers = sync.Pool{New: func() any { return make([]byte, relayBufferSize) }}

func relay(ctx context.Context, a, b net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyOneWay := func(destination, source net.Conn) {
		defer wait.Done()
		buf := relayBuffers.Get().([]byte)
		defer relayBuffers.Put(buf)
		_, _ = io.CopyBuffer(destination, source, buf)
		if halfCloser, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = halfCloser.CloseWrite()
		} else {
			_ = destination.Close()
		}
	}
	go copyOneWay(a, b)
	go copyOneWay(b, a)
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		_ = a.Close()
		_ = b.Close()
		<-done
	}
}

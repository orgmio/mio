package protocal

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	socks5 "github.com/things-go/go-socks5"
)

type SOCKS5Config struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
}

func (c SOCKS5Config) Address() string {
	return net.JoinHostPort(c.Listen, strconv.Itoa(c.Port))
}

type UDPExchangeFunc func(context.Context, string, []byte) ([]byte, error)

type SOCKS5Server struct {
	config SOCKS5Config
	server *socks5.Server
}

func NewSOCKS5ServerWithTransport(config SOCKS5Config, dialContext func(context.Context, string, string) (net.Conn, error), udpExchange UDPExchangeFunc) *SOCKS5Server {
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.Default())),
		socks5.WithResolver(remoteResolver{}),
		socks5.WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
			if network == "udp" {
				return newUDPExchangeConn(ctx, address, udpExchange), nil
			}
			return dialContext(ctx, network, address)
		}),
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

type udpExchangeConn struct {
	ctx       context.Context
	target    string
	exchange  UDPExchangeFunc
	responses chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	deadline  time.Time
}

func newUDPExchangeConn(ctx context.Context, target string, exchange UDPExchangeFunc) net.Conn {
	return &udpExchangeConn{
		ctx:       ctx,
		target:    target,
		exchange:  exchange,
		responses: make(chan []byte, 1),
		closed:    make(chan struct{}),
	}
}

func (c *udpExchangeConn) Write(payload []byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	ctx := c.ctx
	cancel := func() {}
	if deadline.IsZero() {
		ctx, cancel = context.WithTimeout(ctx, tunnelDialTimeout)
	} else {
		ctx, cancel = context.WithDeadline(ctx, deadline)
	}
	defer cancel()
	response, err := c.exchange(ctx, c.target, append([]byte(nil), payload...))
	if err != nil {
		return 0, err
	}
	select {
	case c.responses <- response:
		return len(payload), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (c *udpExchangeConn) Read(buffer []byte) (int, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()

	var timer <-chan time.Time
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, timeoutError{}
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		timer = t.C
	}
	select {
	case response := <-c.responses:
		return copy(buffer, response), nil
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-timer:
		return 0, timeoutError{}
	}
}

func (c *udpExchangeConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *udpExchangeConn) LocalAddr() net.Addr  { return tunnelAddr("ixa-client") }
func (c *udpExchangeConn) RemoteAddr() net.Addr { return tunnelAddr(c.target) }

func (c *udpExchangeConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *udpExchangeConn) SetReadDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

func (c *udpExchangeConn) SetWriteDeadline(deadline time.Time) error {
	return c.SetDeadline(deadline)
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "udp" }
func (a tunnelAddr) String() string  { return string(a) }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

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

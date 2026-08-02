package protocal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion5       = 5
	socksNoAuth         = 0
	socksNoAcceptable   = 0xff
	socksCommandConnect = 1
	socksAddressIPv4    = 1
	socksAddressDomain  = 3
	socksAddressIPv6    = 4
)

type SOCKS5Config struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
}

func (c SOCKS5Config) Address() string {
	return net.JoinHostPort(c.Listen, strconv.Itoa(c.Port))
}

type SOCKS5Server struct {
	config      SOCKS5Config
	dialContext func(context.Context, string, string) (net.Conn, error)
	mu          sync.Mutex
	clients     map[net.Conn]struct{}
}

func NewSOCKS5Server(config SOCKS5Config) *SOCKS5Server {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return NewSOCKS5ServerWithDialer(config, dialer.DialContext)
}

func NewSOCKS5ServerWithDialer(config SOCKS5Config, dialContext func(context.Context, string, string) (net.Conn, error)) *SOCKS5Server {
	return &SOCKS5Server{
		config:      config,
		dialContext: dialContext,
		clients:     make(map[net.Conn]struct{}),
	}
}

func (s *SOCKS5Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.Address())
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
		s.closeClients()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				log.Printf("temporary accept error: %v", err)
				continue
			}
			return err
		}
		s.track(conn, true)
		go func() {
			defer s.track(conn, false)
			defer conn.Close()
			if err := s.handle(ctx, conn); err != nil && ctx.Err() == nil {
				log.Printf("SOCKS5 client %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func (s *SOCKS5Server) handle(ctx context.Context, client net.Conn) error {
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := negotiateAuthentication(client); err != nil {
		return err
	}
	target, err := readConnectRequest(client)
	if err != nil {
		return err
	}

	upstream, err := s.dialContext(ctx, "tcp", target)
	if err != nil {
		_ = writeReply(client, replyForDialError(err), nil)
		return fmt.Errorf("connect to %s: %w", target, err)
	}
	defer upstream.Close()
	if err := writeReply(client, 0, upstream.LocalAddr()); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	log.Printf("SOCKS5 CONNECT %s -> %s", client.RemoteAddr(), target)
	relay(client, upstream)
	return nil
}

func negotiateAuthentication(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == socksNoAuth {
			_, err := conn.Write([]byte{socksVersion5, socksNoAuth})
			return err
		}
	}
	_, _ = conn.Write([]byte{socksVersion5, socksNoAcceptable})
	return errors.New("client does not support no-authentication method")
}

func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socksVersion5 || header[2] != 0 {
		_ = writeReply(conn, 1, nil)
		return "", errors.New("malformed SOCKS5 request")
	}
	if header[1] != socksCommandConnect {
		_ = writeReply(conn, 7, nil)
		return "", fmt.Errorf("unsupported SOCKS5 command %d", header[1])
	}

	var host string
	switch header[3] {
	case socksAddressIPv4:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case socksAddressIPv6:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case socksAddressDomain:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		if length[0] == 0 {
			_ = writeReply(conn, 8, nil)
			return "", errors.New("empty SOCKS5 domain name")
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return "", err
		}
		host = string(address)
	default:
		_ = writeReply(conn, 8, nil)
		return "", fmt.Errorf("unsupported SOCKS5 address type %d", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
}

func writeReply(conn net.Conn, reply byte, address net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		ip = tcpAddress.IP
		port = tcpAddress.Port
	}
	response := []byte{socksVersion5, reply, 0}
	if ip4 := ip.To4(); ip4 != nil {
		response = append(response, socksAddressIPv4)
		response = append(response, ip4...)
	} else {
		response = append(response, socksAddressIPv6)
		response = append(response, ip.To16()...)
	}
	response = binary.BigEndian.AppendUint16(response, uint16(port))
	_, err := conn.Write(response)
	return err
}

func replyForDialError(err error) byte {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return 4
	}
	var operationError *net.OpError
	if errors.As(err, &operationError) {
		if errors.Is(operationError.Err, context.DeadlineExceeded) {
			return 6
		}
		return 5
	}
	return 1
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

func (s *SOCKS5Server) track(conn net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.clients[conn] = struct{}{}
	} else {
		delete(s.clients, conn)
	}
}

func (s *SOCKS5Server) closeClients() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.clients {
		_ = conn.Close()
	}
}

package protocal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	tunnelMagic       = "IXA1"
	authNonceSize     = 16
	authMACSize       = sha256.Size
	maxTargetSize     = 1024
	maxClockSkew      = 30 * time.Second
	tunnelDialTimeout = 10 * time.Second
)

type PeerConfig struct {
	Server   string `toml:"server"`
	Port     int    `toml:"port"`
	LinkPort int    `toml:"link_port"` // Reserved for the HTTP redirect POC stage.
	Key      string `toml:"key"`
	SNI      string `toml:"sni"`
}

type TunnelServerConfig struct {
	Listen   string `toml:"listen"`
	Port     int    `toml:"port"`
	LinkPort int    `toml:"link_port"` // Reserved for the HTTP redirect POC stage.
	Key      string `toml:"key"`
	SNI      string `toml:"sni"`
}

func (c PeerConfig) Address() string {
	return net.JoinHostPort(c.Server, strconv.Itoa(c.Port))
}

func (c TunnelServerConfig) Address() string {
	return net.JoinHostPort(c.Listen, strconv.Itoa(c.Port))
}

type TunnelClient struct {
	config PeerConfig
	key    []byte
	dialer net.Dialer
}

func NewTunnelClient(config PeerConfig) (*TunnelClient, error) {
	key, err := decodeKey(config.Key)
	if err != nil {
		return nil, err
	}
	return &TunnelClient{
		config: config,
		key:    key,
		dialer: net.Dialer{Timeout: tunnelDialTimeout, KeepAlive: 30 * time.Second},
	}, nil
}

func (c *TunnelClient) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("ixa POC only supports TCP, got %q", network)
	}
	raw, err := c.dialer.DialContext(ctx, "tcp", c.config.Address())
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         c.config.SNI,
		InsecureSkipVerify: true, // POC: the ephemeral server certificate cannot be verified.
		NextProtos:         []string{"http/1.1"},
	})
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(tunnelDialTimeout)
	}
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	if err := writeTunnelRequest(tlsConn, c.key, target, time.Now()); err != nil {
		tlsConn.Close()
		return nil, err
	}
	response := []byte{0}
	if _, err := io.ReadFull(tlsConn, response); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("read tunnel response: %w", err)
	}
	if response[0] != 0 {
		tlsConn.Close()
		return nil, fmt.Errorf("tunnel server rejected target (code %d)", response[0])
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

type TunnelServer struct {
	config      TunnelServerConfig
	key         []byte
	tlsConfig   *tls.Config
	dialContext func(context.Context, string, string) (net.Conn, error)
	mu          sync.Mutex
	clients     map[net.Conn]struct{}
}

func NewTunnelServer(config TunnelServerConfig) (*TunnelServer, error) {
	key, err := decodeKey(config.Key)
	if err != nil {
		return nil, err
	}
	certificate, err := ephemeralCertificate(config.SNI)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral certificate: %w", err)
	}
	dialer := &net.Dialer{Timeout: tunnelDialTimeout, KeepAlive: 30 * time.Second}
	return &TunnelServer{
		config: config,
		key:    key,
		tlsConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		},
		dialContext: dialer.DialContext,
		clients:     make(map[net.Conn]struct{}),
	}, nil
}

func (s *TunnelServer) ListenAndServe(ctx context.Context) error {
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
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.track(raw, true)
		go func() {
			defer s.track(raw, false)
			defer raw.Close()
			if err := s.handle(ctx, tls.Server(raw, s.tlsConfig)); err != nil && ctx.Err() == nil {
				log.Printf("ixa client %s: %v", raw.RemoteAddr(), err)
			}
		}()
	}
}

func (s *TunnelServer) handle(ctx context.Context, client net.Conn) error {
	_ = client.SetDeadline(time.Now().Add(tunnelDialTimeout))
	target, err := readTunnelRequest(client, s.key, time.Now())
	if err != nil {
		return err
	}
	upstream, err := s.dialContext(ctx, "tcp", target)
	if err != nil {
		_, _ = client.Write([]byte{1})
		return fmt.Errorf("connect to %s: %w", target, err)
	}
	defer upstream.Close()
	if _, err := client.Write([]byte{0}); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	log.Printf("ixa CONNECT %s -> %s", client.RemoteAddr(), target)
	relay(client, upstream)
	return nil
}

func writeTunnelRequest(w io.Writer, key []byte, target string, now time.Time) error {
	if len(target) == 0 || len(target) > maxTargetSize {
		return fmt.Errorf("invalid target length %d", len(target))
	}
	header := make([]byte, 0, len(tunnelMagic)+8+authNonceSize)
	header = append(header, tunnelMagic...)
	header = binary.BigEndian.AppendUint64(header, uint64(now.Unix()))
	nonce := make([]byte, authNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	header = append(header, nonce...)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(header)
	_, _ = mac.Write([]byte(target))
	packet := append(header, mac.Sum(nil)...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(target)))
	packet = append(packet, target...)
	_, err := w.Write(packet)
	return err
}

func readTunnelRequest(r io.Reader, key []byte, now time.Time) (string, error) {
	header := make([]byte, len(tunnelMagic)+8+authNonceSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}
	if string(header[:len(tunnelMagic)]) != tunnelMagic {
		return "", errors.New("invalid tunnel preface")
	}
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(header[len(tunnelMagic):])), 0)
	if delta := now.Sub(timestamp); delta > maxClockSkew || delta < -maxClockSkew {
		return "", errors.New("authentication timestamp outside allowed window")
	}
	receivedMAC := make([]byte, authMACSize)
	if _, err := io.ReadFull(r, receivedMAC); err != nil {
		return "", err
	}
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, lengthBytes); err != nil {
		return "", err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes))
	if length == 0 || length > maxTargetSize {
		return "", fmt.Errorf("invalid target length %d", length)
	}
	targetBytes := make([]byte, length)
	if _, err := io.ReadFull(r, targetBytes); err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(header)
	_, _ = mac.Write(targetBytes)
	if !hmac.Equal(receivedMAC, mac.Sum(nil)) {
		return "", errors.New("tunnel authentication failed")
	}
	return string(targetBytes), nil
}

func decodeKey(value string) ([]byte, error) {
	key, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("key must be hexadecimal")
	}
	if len(key) < 16 {
		return nil, errors.New("key must contain at least 16 bytes")
	}
	return key, nil
}

func ephemeralCertificate(serverName string) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, nil
}

func (s *TunnelServer) track(conn net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.clients[conn] = struct{}{}
	} else {
		delete(s.clients, conn)
	}
}

func (s *TunnelServer) closeClients() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.clients {
		_ = conn.Close()
	}
}

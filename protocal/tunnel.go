package protocal

import (
	"bytes"
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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	tlsfork "github.com/refraction-networking/utls"
)

const (
	tunnelMagic       = "IXA1"
	authNonceSize     = 16
	authMACSize       = sha256.Size
	maxTargetSize     = 1024
	maxClockSkew      = 30 * time.Second
	tunnelDialTimeout = 10 * time.Second
	clientRandomSize  = 32
	clientNonceSize   = 8
	clientTagSize     = 16
	maxClientHello    = 64 * 1024
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
	cover  coverTarget
	dialer net.Dialer
}

func NewTunnelClient(config PeerConfig) (*TunnelClient, error) {
	key, err := decodeKey(config.Key)
	if err != nil {
		return nil, err
	}
	cover, err := parseCoverTarget(config.SNI)
	if err != nil {
		return nil, fmt.Errorf("invalid peer.sni: %w", err)
	}
	return &TunnelClient{
		config: config,
		key:    key,
		cover:  cover,
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
	authRandom, err := makeAuthenticatedRandom(c.key, c.cover.host, time.Now())
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("create ClientHello authentication: %w", err)
	}
	observed := &serverHelloObserverConn{Conn: raw}
	tlsConn := tlsfork.Client(observed, &tlsfork.Config{
		MinVersion:                    tlsfork.VersionTLS13,
		ServerName:                    c.cover.host,
		InsecureSkipVerify:            true,
		InsecureSkipCertificateVerify: true,
		NextProtos:                    []string{"http/1.1"},
		Rand:                          io.MultiReader(bytes.NewReader(authRandom), rand.Reader),
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
	serverRandom, err := readServerHelloRandom(observed.Bytes())
	if err != nil || !verifyServerAuthenticatedRandom(c.key, c.cover.host, authRandom, serverRandom, time.Now()) {
		tlsConn.Close()
		if err != nil {
			return nil, fmt.Errorf("verify ServerHello authentication: %w", err)
		}
		return nil, errors.New("ServerHello HMAC authentication failed")
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
	cover       coverTarget
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
	cover, err := parseCoverTarget(config.SNI)
	if err != nil {
		return nil, fmt.Errorf("invalid server.sni: %w", err)
	}
	certificate, err := ephemeralCertificate(cover.host)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral certificate: %w", err)
	}
	dialer := &net.Dialer{Timeout: tunnelDialTimeout, KeepAlive: 30 * time.Second}
	return &TunnelServer{
		config: config,
		key:    key,
		cover:  cover,
		tlsConfig: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			Certificates:           []tls.Certificate{certificate},
			NextProtos:             []string{"http/1.1"},
			SessionTicketsDisabled: true,
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
			if err := s.serveRaw(ctx, raw); err != nil && ctx.Err() == nil {
				log.Printf("ixa client %s: %v", raw.RemoteAddr(), err)
			}
		}()
	}
}

func (s *TunnelServer) serveRaw(ctx context.Context, raw net.Conn) error {
	_ = raw.SetReadDeadline(time.Now().Add(tunnelDialTimeout))
	preface, clientRandom, err := readClientHelloRandom(raw)
	if err != nil || !verifyAuthenticatedRandom(s.key, s.cover.host, clientRandom, time.Now()) {
		_ = raw.SetReadDeadline(time.Time{})
		return s.fallback(ctx, raw, preface)
	}
	_ = raw.SetReadDeadline(time.Time{})
	replayed := &replayConn{Conn: raw, reader: io.MultiReader(bytes.NewReader(preface), raw)}
	serverRandom, err := makeServerAuthenticatedRandom(s.key, s.cover.host, clientRandom, time.Now())
	if err != nil {
		return fmt.Errorf("create ServerHello authentication: %w", err)
	}
	tlsConfig := s.tlsConfig.Clone()
	tlsConfig.Rand = io.MultiReader(bytes.NewReader(serverRandom), rand.Reader)
	return s.handle(ctx, tls.Server(replayed, tlsConfig))
}

func (s *TunnelServer) fallback(ctx context.Context, client net.Conn, preface []byte) error {
	dialer := &net.Dialer{Timeout: tunnelDialTimeout, KeepAlive: 30 * time.Second}
	target := s.cover.address
	upstream, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("fallback to %s: %w", target, err)
	}
	defer upstream.Close()
	if len(preface) != 0 {
		if _, err := upstream.Write(preface); err != nil {
			return fmt.Errorf("write fallback preface: %w", err)
		}
	}
	log.Printf("TLS fallback %s -> %s", client.RemoteAddr(), target)
	relay(client, upstream)
	return nil
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

func makeAuthenticatedRandom(key []byte, serverName string, now time.Time) ([]byte, error) {
	result := make([]byte, clientRandomSize)
	nonce := result[:clientNonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	mask := hmacSum(key, []byte("ixa-client-random-mask"), nonce, []byte(serverName))
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(now.Unix()))
	for i := range timestamp {
		result[clientNonceSize+i] = timestamp[i] ^ mask[i]
	}
	tag := hmacSum(key, []byte("ixa-client-random-auth"), result[:16], []byte(serverName))
	copy(result[16:], tag[:clientTagSize])
	return result, nil
}

func verifyAuthenticatedRandom(key []byte, serverName string, value []byte, now time.Time) bool {
	if len(value) != clientRandomSize {
		return false
	}
	expected := hmacSum(key, []byte("ixa-client-random-auth"), value[:16], []byte(serverName))
	if !hmac.Equal(value[16:], expected[:clientTagSize]) {
		return false
	}
	mask := hmacSum(key, []byte("ixa-client-random-mask"), value[:clientNonceSize], []byte(serverName))
	timestampBytes := make([]byte, 8)
	for i := range timestampBytes {
		timestampBytes[i] = value[clientNonceSize+i] ^ mask[i]
	}
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(timestampBytes)), 0)
	delta := now.Sub(timestamp)
	return delta <= maxClockSkew && delta >= -maxClockSkew
}

func makeServerAuthenticatedRandom(key []byte, serverName string, clientRandom []byte, now time.Time) ([]byte, error) {
	return makeBoundAuthenticatedRandom(key, "ixa-server-random", serverName, clientRandom, now)
}

func verifyServerAuthenticatedRandom(key []byte, serverName string, clientRandom, value []byte, now time.Time) bool {
	return verifyBoundAuthenticatedRandom(key, "ixa-server-random", serverName, clientRandom, value, now)
}

func makeBoundAuthenticatedRandom(key []byte, label, serverName string, binding []byte, now time.Time) ([]byte, error) {
	result := make([]byte, clientRandomSize)
	nonce := result[:clientNonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	mask := hmacSum(key, []byte(label+"-mask"), nonce, binding, []byte(serverName))
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(now.Unix()))
	for i := range timestamp {
		result[clientNonceSize+i] = timestamp[i] ^ mask[i]
	}
	tag := hmacSum(key, []byte(label+"-auth"), result[:16], binding, []byte(serverName))
	copy(result[16:], tag[:clientTagSize])
	return result, nil
}

func verifyBoundAuthenticatedRandom(key []byte, label, serverName string, binding, value []byte, now time.Time) bool {
	if len(value) != clientRandomSize {
		return false
	}
	expected := hmacSum(key, []byte(label+"-auth"), value[:16], binding, []byte(serverName))
	if !hmac.Equal(value[16:], expected[:clientTagSize]) {
		return false
	}
	mask := hmacSum(key, []byte(label+"-mask"), value[:clientNonceSize], binding, []byte(serverName))
	timestampBytes := make([]byte, 8)
	for i := range timestampBytes {
		timestampBytes[i] = value[clientNonceSize+i] ^ mask[i]
	}
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(timestampBytes)), 0)
	delta := now.Sub(timestamp)
	return delta <= maxClockSkew && delta >= -maxClockSkew
}

func hmacSum(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

func readClientHelloRandom(r io.Reader) (preface, clientRandom []byte, err error) {
	var handshake bytes.Buffer
	for handshake.Len() < maxClientHello {
		header := make([]byte, 5)
		if _, err = io.ReadFull(r, header); err != nil {
			return preface, nil, err
		}
		preface = append(preface, header...)
		if header[0] != 22 {
			return preface, nil, errors.New("first TLS record is not a handshake")
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || len(preface)+length > maxClientHello {
			return preface, nil, errors.New("invalid TLS ClientHello length")
		}
		payload := make([]byte, length)
		if _, err = io.ReadFull(r, payload); err != nil {
			return preface, nil, err
		}
		preface = append(preface, payload...)
		handshake.Write(payload)
		data := handshake.Bytes()
		if len(data) < 4 {
			continue
		}
		if data[0] != 1 {
			return preface, nil, errors.New("first TLS handshake message is not ClientHello")
		}
		messageLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if messageLength < 34 || messageLength > maxClientHello {
			return preface, nil, errors.New("invalid TLS ClientHello message length")
		}
		if len(data) < 4+messageLength {
			continue
		}
		return preface, append([]byte(nil), data[6:38]...), nil
	}
	return preface, nil, errors.New("TLS ClientHello exceeds limit")
}

func readServerHelloRandom(records []byte) ([]byte, error) {
	var handshake bytes.Buffer
	for len(records) >= 5 {
		length := int(binary.BigEndian.Uint16(records[3:5]))
		if len(records) < 5+length {
			return nil, errors.New("incomplete TLS record containing ServerHello")
		}
		if records[0] == 22 {
			handshake.Write(records[5 : 5+length])
			data := handshake.Bytes()
			if len(data) >= 4 {
				if data[0] != 2 {
					return nil, errors.New("first server handshake message is not ServerHello")
				}
				messageLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
				if messageLength < 34 || messageLength > maxClientHello {
					return nil, errors.New("invalid TLS ServerHello message length")
				}
				if len(data) >= 4+messageLength {
					return append([]byte(nil), data[6:38]...), nil
				}
			}
		}
		records = records[5+length:]
	}
	return nil, errors.New("TLS ServerHello not found")
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

type serverHelloObserverConn struct {
	net.Conn
	observed bytes.Buffer
}

func (c *serverHelloObserverConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if remaining := maxClientHello - c.observed.Len(); remaining > 0 {
		keep := n
		if keep > remaining {
			keep = remaining
		}
		_, _ = c.observed.Write(p[:keep])
	}
	return n, err
}

func (c *serverHelloObserverConn) Bytes() []byte {
	return c.observed.Bytes()
}

type coverTarget struct {
	host    string
	address string
}

func parseCoverTarget(value string) (coverTarget, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return coverTarget{}, errors.New("must not be empty")
	}
	if !strings.HasPrefix(value, "https://") {
		return coverTarget{}, errors.New(`must use the form "https://example.com:443"`)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return coverTarget{}, err
	}
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return coverTarget{}, errors.New(`must use the form "https://example.com:443" without credentials, path, query, or fragment`)
	}
	host := parsed.Hostname()
	if host == "" {
		return coverTarget{}, errors.New("missing hostname")
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil || port == "0" {
		return coverTarget{}, errors.New("port must be between 1 and 65535")
	}
	return coverTarget{host: host, address: net.JoinHostPort(host, port)}, nil
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
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

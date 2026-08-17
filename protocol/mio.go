package mio

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/orgmio/quic-mio"
	"github.com/orgmio/quic-mio/http3"
	tlsfork "github.com/orgmio/utls-mio"
	"golang.org/x/net/http2"
)

const (
	tunnelMagic       = "MIO1"
	authNonceSize     = 16
	authMACSize       = sha256.Size
	maxTargetSize     = 1024
	maxClockSkew      = 30 * time.Second
	tunnelDialTimeout = 10 * time.Second
	// How long the SOCKS client will wait to get a tunnel stream.
	// Origin dial happens after the stream is already open.
	clientDialTimeout = 5 * time.Second
	// How long the server waits for the destination website.
	originDialTimeout = 4 * time.Second
	clientRandomSize  = 32
	clientNonceSize   = 8
	clientTagSize     = 16
	maxClientHello    = 64 * 1024
	tunnelCommandTCP  = 1
	tunnelCommandUDP  = 3
	maxUDPPayload     = 65507
)

type PeerConfig struct {
	Server string `toml:"server"`
	Port   int    `toml:"port"`
	Key    string `toml:"key"`
	SNI    string `toml:"sni"`
}

type TunnelServerConfig struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
	Key    string `toml:"key"`
	SNI    string `toml:"sni"`
}

func (c PeerConfig) Address() string {
	return net.JoinHostPort(c.Server, strconv.Itoa(c.Port))
}

func (c TunnelServerConfig) Address() string {
	return net.JoinHostPort(c.Listen, strconv.Itoa(c.Port))
}

type TunnelClient struct {
	config         PeerConfig
	key            []byte
	cover          coverTarget
	dialer         net.Dialer
	quicMu         sync.Mutex
	quicConn       *quic.Conn
	quicPacketConn net.PacketConn
	quicDialing    bool
	quicDialDone   chan struct{}
	quicDialErr    error
	quicUpgrading  bool
	h3Transport    *http3.Transport
	h2Mu           sync.Mutex
	h2Transport    *http2.Transport
	h2Conn         net.Conn
}

func NewTunnelClient(config PeerConfig) (*TunnelClient, error) {
	key, err := decodeKey(config.Key)
	if err != nil {
		return nil, err
	}
	cover, err := parseCover(config.SNI)
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
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, clientDialTimeout)
		defer cancel()
	}
	switch network {
	case "tcp":
		return c.openTunnel(ctx, tunnelCommandTCP, target)
	case "udp":
		conn, err := c.openTunnel(ctx, tunnelCommandUDP, target)
		if err != nil {
			return nil, err
		}
		return newFramedUDP(conn), nil
	default:
		return nil, fmt.Errorf("mio does not support network %q", network)
	}
}

type framedUDPConn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func newFramedUDP(conn net.Conn) net.Conn { return &framedUDPConn{Conn: conn} }

func (c *framedUDPConn) Write(payload []byte) (int, error) {
	if len(payload) > maxUDPPayload {
		return 0, fmt.Errorf("UDP payload exceeds %d bytes", maxUDPPayload)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	packet := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
	packet = append(packet, payload...)
	if err := writeAll(c.Conn, packet); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *framedUDPConn) Read(buffer []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var lengthBytes [2]byte
	if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return 0, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length > len(buffer) {
		if _, err := io.CopyN(io.Discard, c.Conn, int64(length)); err != nil {
			return 0, err
		}
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.Conn, buffer[:length])
}

func (c *TunnelClient) openTunnel(ctx context.Context, command byte, target string) (net.Conn, error) {
	c.startQUICUpgrade()
	if c.hasQUIC() {
		conn, err := c.openQUIC(ctx, command, target)
		if err == nil {
			return conn, nil
		}
		var rejected *tunnelRejectedError
		if errors.As(err, &rejected) {
			return nil, err
		}
		log.Printf("HTTP/3 unavailable for %s, downgrading to TCP: %v", target, err)
	}
	return c.openTCPCover(ctx, command, target)
}

func (c *TunnelClient) dialCoverTLS(ctx context.Context) (*tlsfork.UConn, error) {
	raw, err := c.dialer.DialContext(ctx, "tcp", c.config.Address())
	if err != nil {
		return nil, err
	}
	preferTCPBBR(raw)
	authRandom, err := makeAuthRandom(c.key, c.cover.host, time.Now())
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("create ClientHello authentication: %w", err)
	}
	observed := &serverHelloObserverConn{Conn: raw}
	tlsConn := tlsfork.UClient(observed, &tlsfork.Config{
		MinVersion:                    tlsfork.VersionTLS13,
		ServerName:                    c.cover.host,
		InsecureSkipVerify:            true,
		InsecureSkipCertificateVerify: true,
		NextProtos:                    []string{coverHTTP2ALPN, coverHTTP1ALPN},
	}, tlsfork.HelloChrome_Auto)
	pinBraveECH(tlsConn)
	if err := tlsConn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("build Chrome ClientHello: %w", err)
	}
	tlsConn.HandshakeState.Hello.Random = append([]byte(nil), authRandom...)
	applyBraveSigAlgs(tlsConn)
	reorderBraveExtensions(tlsConn)
	if err := tlsConn.BuildHandshakeState(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("build Brave 1.93 ClientHello: %w", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(tunnelDialTimeout)
	}
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	serverRandom, err := readServerRandom(observed.Bytes())
	if err != nil || !verifyServerRandom(c.key, c.cover.host, authRandom, serverRandom, time.Now()) {
		tlsConn.Close()
		if err != nil {
			return nil, fmt.Errorf("verify ServerHello authentication: %w", err)
		}
		return nil, errors.New("ServerHello HMAC authentication failed")
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func applyBraveSigAlgs(conn *tlsfork.UConn) {
	algorithms := []tlsfork.SignatureScheme{
		tlsfork.SignatureScheme(0x0904), // ML-DSA-44
		tlsfork.SignatureScheme(0x0905), // ML-DSA-65
		tlsfork.SignatureScheme(0x0906), // ML-DSA-87
		tlsfork.ECDSAWithP256AndSHA256,
		tlsfork.PSSWithSHA256,
		tlsfork.PKCS1WithSHA256,
		tlsfork.ECDSAWithP384AndSHA384,
		tlsfork.PSSWithSHA384,
		tlsfork.PKCS1WithSHA384,
		tlsfork.PSSWithSHA512,
		tlsfork.PKCS1WithSHA512,
	}
	for _, extension := range conn.Extensions {
		if signatureAlgorithms, ok := extension.(*tlsfork.SignatureAlgorithmsExtension); ok {
			signatureAlgorithms.SupportedSignatureAlgorithms = append([]tlsfork.SignatureScheme(nil), algorithms...)
			break
		}
	}
	conn.HandshakeState.Hello.SupportedSignatureAlgorithms = append([]tlsfork.SignatureScheme(nil), algorithms...)
}

// pinBraveECH forces the GREASE ECH payload so the extension length is 250
// bytes, matching way-brave-caddy-baidu.pcapng (HelloChrome_Auto defaults
// to 186). Must run before the first BuildHandshakeState.
func pinBraveECH(conn *tlsfork.UConn) {
	for _, extension := range conn.Extensions {
		if ech, ok := extension.(*tlsfork.GREASEEncryptedClientHelloExtension); ok {
			ech.CandidatePayloadLens = []uint16{192}
			return
		}
	}
}

// braveExtensionRank returns the position of a ClientHello extension in the
// real Brave (Chromium 151) ClientHello captured in
// caddy-real/way-brave-caddy-baidu.pcapng. utls's HelloChrome_Auto preset
// shuffles Chrome extensions; Brave emits a fixed order, so we pin it down
// for a byte-identical JA3 fingerprint.
func braveExtensionRank(ext tlsfork.TLSExtension) int {
	switch e := ext.(type) {
	case *tlsfork.UtlsGREASEExtension:
		if len(e.Body) == 0 {
			return 0 // leading GREASE
		}
		return 17 // trailing GREASE with a single zero byte
	case *tlsfork.KeyShareExtension:
		return 1
	case *tlsfork.SignatureAlgorithmsExtension:
		return 2
	case *tlsfork.ExtendedMasterSecretExtension:
		return 3
	case *tlsfork.SNIExtension:
		return 4
	case *tlsfork.StatusRequestExtension:
		return 5
	case *tlsfork.UtlsCompressCertExtension:
		return 6
	case *tlsfork.ALPNExtension:
		return 7
	case *tlsfork.ApplicationSettingsExtension, *tlsfork.ApplicationSettingsExtensionNew:
		return 8
	case *tlsfork.RenegotiationInfoExtension:
		return 9
	case *tlsfork.SupportedVersionsExtension:
		return 10
	case *tlsfork.GREASEEncryptedClientHelloExtension:
		return 11
	case *tlsfork.SessionTicketExtension:
		return 12
	case *tlsfork.SCTExtension:
		return 13
	case *tlsfork.SupportedCurvesExtension:
		return 14
	case *tlsfork.SupportedPointsExtension:
		return 15
	case *tlsfork.PSKKeyExchangeModesExtension:
		return 16
	default:
		return 18
	}
}

// reorderBraveExtensions arranges the built Chrome ClientHello extensions in
// the fixed order emitted by the captured Brave build.
func reorderBraveExtensions(conn *tlsfork.UConn) {
	sort.SliceStable(conn.Extensions, func(i, j int) bool {
		return braveExtensionRank(conn.Extensions[i]) < braveExtensionRank(conn.Extensions[j])
	})
}

type TunnelServer struct {
	config      TunnelServerConfig
	key         []byte
	cover       coverTarget
	tlsConfig   *tls.Config
	dialContext func(context.Context, string, string) (net.Conn, error)
	mu          sync.Mutex
	clients     map[net.Conn]struct{}
	udpMu       sync.Mutex
	udpSessions map[string]*udpForwardSession
}

func NewTunnelServer(config TunnelServerConfig) (*TunnelServer, error) {
	return newServer(config, fetchCoverCert)
}

func newServer(config TunnelServerConfig, loadCertificate func(coverTarget) (tls.Certificate, error)) (*TunnelServer, error) {
	key, err := decodeKey(config.Key)
	if err != nil {
		return nil, err
	}
	cover, err := parseCover(config.SNI)
	if err != nil {
		return nil, fmt.Errorf("invalid server.sni: %w", err)
	}
	certificate, err := loadCertificate(cover)
	if err != nil {
		return nil, fmt.Errorf("load certificate from %s: %w", cover.address, err)
	}
	dialer := &net.Dialer{Timeout: tunnelDialTimeout, KeepAlive: 30 * time.Second}
	return &TunnelServer{
		config: config,
		key:    key,
		cover:  cover,
		tlsConfig: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			Certificates:           []tls.Certificate{certificate},
			NextProtos:             []string{coverHTTP2ALPN, coverHTTP1ALPN},
			SessionTicketsDisabled: true,
		},
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if _, ok := ctx.Deadline(); !ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, originDialTimeout)
				defer cancel()
			}
			conn, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			if network == "tcp" {
				preferTCPBBR(conn)
			}
			return conn, nil
		},
		clients:     make(map[net.Conn]struct{}),
		udpSessions: make(map[string]*udpForwardSession),
	}, nil
}

func fetchCoverCert(cover coverTarget) (tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tunnelDialTimeout)
	defer cancel()
	dialer := &net.Dialer{Timeout: tunnelDialTimeout, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", cover.address)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: cover.host,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return tls.Certificate{}, fmt.Errorf("TLS handshake and certificate verification: %w", err)
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return tls.Certificate{}, errors.New("cover server returned no certificate")
	}
	privateKey, err := signKey(state.PeerCertificates[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	chain := make([][]byte, len(state.PeerCertificates))
	for i, certificate := range state.PeerCertificates {
		chain[i] = append([]byte(nil), certificate.Raw...)
	}
	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  privateKey,
		Leaf:        state.PeerCertificates[0],
	}, nil
}

func signKey(certificate *x509.Certificate) (crypto.Signer, error) {
	switch publicKey := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.GenerateKey(rand.Reader, max(2048, publicKey.N.BitLen()))
	case *ecdsa.PublicKey:
		return ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	case ed25519.PublicKey:
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		return privateKey, err
	default:
		return nil, fmt.Errorf("unsupported cover certificate public key type %T", certificate.PublicKey)
	}
}

func (s *TunnelServer) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.config.Address())
	if err != nil {
		return err
	}
	defer listener.Close()
	udpAddress, err := net.ResolveUDPAddr("udp", s.config.Address())
	if err != nil {
		return err
	}
	udpListener, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	raiseUDPBuffers(udpListener)
	defer udpListener.Close()
	udpErrors := make(chan error, 1)
	go func() {
		udpErr := s.serveQUIC(ctx, udpListener)
		udpErrors <- udpErr
		if udpErr != nil {
			_ = listener.Close()
		}
	}()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		_ = udpListener.Close()
		s.closeClients()
		s.closeUDP()
	}()
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			select {
			case udpErr := <-udpErrors:
				if udpErr != nil {
					return fmt.Errorf("serve UDP fallback: %w", udpErr)
				}
			default:
			}
			return err
		}
		preferTCPBBR(raw)
		s.track(raw, true)
		go func() {
			defer s.track(raw, false)
			defer raw.Close()
			if err := s.serveRaw(ctx, raw); err != nil && ctx.Err() == nil {
				log.Printf("mio client %s: %v", raw.RemoteAddr(), err)
			}
		}()
	}
}

func (s *TunnelServer) serveRaw(ctx context.Context, raw net.Conn) error {
	_ = raw.SetReadDeadline(time.Now().Add(tunnelDialTimeout))
	preface, clientRandom, err := readClientRandom(raw)
	if err != nil || !verifyAuthRandom(s.key, s.cover.host, clientRandom, time.Now()) {
		_ = raw.SetReadDeadline(time.Time{})
		return s.fallback(ctx, raw, preface)
	}
	_ = raw.SetReadDeadline(time.Time{})
	replayed := &replayConn{Conn: raw, reader: io.MultiReader(bytes.NewReader(preface), raw)}
	serverRandom, err := makeServerRandom(s.key, s.cover.host, clientRandom, time.Now())
	if err != nil {
		return fmt.Errorf("create ServerHello authentication: %w", err)
	}
	tlsConfig := s.tlsConfig.Clone()
	tlsConfig.Rand = io.MultiReader(bytes.NewReader(serverRandom), rand.Reader)
	return s.serveAuthedTLS(ctx, tls.Server(replayed, tlsConfig))
}

func (s *TunnelServer) fallback(ctx context.Context, client net.Conn, preface []byte) error {
	target := s.cover.address
	upstream, err := s.dialContext(ctx, "tcp", target)
	if err != nil {
		return fmt.Errorf("fallback to %s: %w", target, err)
	}
	defer upstream.Close()
	if len(preface) != 0 {
		if _, err := upstream.Write(preface); err != nil {
			return fmt.Errorf("write fallback preface: %w", err)
		}
	}
	log.Printf("TCP fallback %s -> %s", client.RemoteAddr(), target)
	relay(ctx, client, upstream)
	return nil
}

func (s *TunnelServer) handle(ctx context.Context, client net.Conn) error {
	_ = client.SetDeadline(time.Now().Add(tunnelDialTimeout))
	command, target, err := readRequest(client, s.key, time.Now())
	if err != nil {
		return err
	}
	network := "tcp"
	if command == tunnelCommandUDP {
		network = "udp"
	} else if command != tunnelCommandTCP {
		_, _ = client.Write([]byte{2})
		return fmt.Errorf("unsupported tunnel command %d", command)
	}
	// Tell the client the stream is open before dialing the website so
	// SOCKS can return success and the browser can move on. A failed
	// origin dial just closes the stream.
	if _, err := client.Write([]byte{0}); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	dialCtx, cancel := context.WithTimeout(ctx, originDialTimeout)
	upstream, err := s.dialContext(dialCtx, network, target)
	cancel()
	if err != nil {
		_ = client.Close()
		return fmt.Errorf("connect to %s: %w", target, err)
	}
	defer upstream.Close()
	if command == tunnelCommandUDP {
		return exchangeUDP(client, upstream, target)
	}
	log.Printf("mio CONNECT %s -> %s", client.RemoteAddr(), target)
	if _, framed := client.(interface{ isCoverStream() }); !framed {
		if _, quic := client.(interface{ isQUICStream() }); !quic {
			client = newVision(client)
		}
	}
	relay(ctx, client, upstream)
	return nil
}

func writeRequest(w io.Writer, key []byte, command byte, target string, now time.Time) error {
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
	header = append(header, command)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(header)
	_, _ = mac.Write([]byte(target))
	packet := append(header, mac.Sum(nil)...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(target)))
	packet = append(packet, target...)
	_, err := w.Write(packet)
	return err
}

func readRequest(r io.Reader, key []byte, now time.Time) (byte, string, error) {
	header := make([]byte, len(tunnelMagic)+8+authNonceSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, "", err
	}
	if string(header[:len(tunnelMagic)]) != tunnelMagic {
		return 0, "", errors.New("invalid tunnel preface")
	}
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(header[len(tunnelMagic):])), 0)
	if delta := now.Sub(timestamp); delta > maxClockSkew || delta < -maxClockSkew {
		return 0, "", errors.New("authentication timestamp outside allowed window")
	}
	commandBytes := []byte{0}
	if _, err := io.ReadFull(r, commandBytes); err != nil {
		return 0, "", err
	}
	header = append(header, commandBytes[0])
	receivedMAC := make([]byte, authMACSize)
	if _, err := io.ReadFull(r, receivedMAC); err != nil {
		return 0, "", err
	}
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, lengthBytes); err != nil {
		return 0, "", err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes))
	if length == 0 || length > maxTargetSize {
		return 0, "", fmt.Errorf("invalid target length %d", length)
	}
	targetBytes := make([]byte, length)
	if _, err := io.ReadFull(r, targetBytes); err != nil {
		return 0, "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(header)
	_, _ = mac.Write(targetBytes)
	if !hmac.Equal(receivedMAC, mac.Sum(nil)) {
		return 0, "", errors.New("tunnel authentication failed")
	}
	return commandBytes[0], string(targetBytes), nil
}

func exchangeUDP(tunnel, upstream net.Conn, target string) error {
	errors := make(chan error, 2)
	go func() {
		err := copyUDP(upstream, newFramedUDP(tunnel))
		if err != nil {
			err = fmt.Errorf("send UDP to %s: %w", target, err)
		}
		errors <- err
	}()
	go func() {
		err := copyUDP(newFramedUDP(tunnel), upstream)
		if err != nil {
			err = fmt.Errorf("receive UDP from %s: %w", target, err)
		}
		errors <- err
	}()
	return <-errors
}

func copyUDP(destination io.Writer, source io.Reader) error {
	buffer := make([]byte, maxUDPPayload)
	for {
		n, err := source.Read(buffer)
		if n > 0 {
			if _, writeErr := destination.Write(buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
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

func makeAuthRandom(key []byte, serverName string, now time.Time) ([]byte, error) {
	result := make([]byte, clientRandomSize)
	nonce := result[:clientNonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	mask := hmacSum(key, []byte("mio-client-random-mask"), nonce, []byte(serverName))
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(now.Unix()))
	for i := range timestamp {
		result[clientNonceSize+i] = timestamp[i] ^ mask[i]
	}
	tag := hmacSum(key, []byte("mio-client-random-auth"), result[:16], []byte(serverName))
	copy(result[16:], tag[:clientTagSize])
	return result, nil
}

func verifyAuthRandom(key []byte, serverName string, value []byte, now time.Time) bool {
	if len(value) != clientRandomSize {
		return false
	}
	expected := hmacSum(key, []byte("mio-client-random-auth"), value[:16], []byte(serverName))
	if !hmac.Equal(value[16:], expected[:clientTagSize]) {
		return false
	}
	mask := hmacSum(key, []byte("mio-client-random-mask"), value[:clientNonceSize], []byte(serverName))
	timestampBytes := make([]byte, 8)
	for i := range timestampBytes {
		timestampBytes[i] = value[clientNonceSize+i] ^ mask[i]
	}
	timestamp := time.Unix(int64(binary.BigEndian.Uint64(timestampBytes)), 0)
	delta := now.Sub(timestamp)
	return delta <= maxClockSkew && delta >= -maxClockSkew
}

func makeServerRandom(key []byte, serverName string, clientRandom []byte, now time.Time) ([]byte, error) {
	return makeBoundRandom(key, "mio-server-random", serverName, clientRandom, now)
}

func verifyServerRandom(key []byte, serverName string, clientRandom, value []byte, now time.Time) bool {
	return verifyBoundRandom(key, "mio-server-random", serverName, clientRandom, value, now)
}

func makeBoundRandom(key []byte, label, serverName string, binding []byte, now time.Time) ([]byte, error) {
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

func verifyBoundRandom(key []byte, label, serverName string, binding, value []byte, now time.Time) bool {
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

func readClientRandom(r io.Reader) (preface, clientRandom []byte, err error) {
	var handshake bytes.Buffer
	for handshake.Len() < maxClientHello {
		header := make([]byte, 5)
		n, readErr := io.ReadFull(r, header)
		preface = append(preface, header[:n]...)
		if readErr != nil {
			err = readErr
			return preface, nil, err
		}
		if header[0] != 22 {
			return preface, nil, errors.New("first TLS record is not a handshake")
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || len(preface)+length > maxClientHello {
			return preface, nil, errors.New("invalid TLS ClientHello length")
		}
		payload := make([]byte, length)
		n, readErr = io.ReadFull(r, payload)
		preface = append(preface, payload[:n]...)
		if readErr != nil {
			err = readErr
			return preface, nil, err
		}
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

func readServerRandom(records []byte) ([]byte, error) {
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

func parseCover(value string) (coverTarget, error) {
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

func tempCert(serverName string) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	coverPadding := make([]byte, 420)
	if _, err := rand.Read(coverPadding); err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{{
			Id:       []int{1, 3, 6, 1, 4, 1, 55555, 1},
			Critical: false,
			Value:    coverPadding,
		}},
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

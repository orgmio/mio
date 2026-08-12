package mio

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	quic "github.com/orgmio/quic-mio"
	"github.com/orgmio/quic-mio/http3"
)

const (
	ixaQUICALPN           = "h3"
	quicProbeTimeout      = 2 * time.Second
	quicWarmupMin         = 250 * time.Millisecond
	quicWarmupMax         = 550 * time.Millisecond
	braveStreamWindow     = 6 * 1024 * 1024
	braveConnectionWindow = 15 * 1024 * 1024
)

type tunnelRejectedError struct{ code byte }

func (e *tunnelRejectedError) Error() string {
	return fmt.Sprintf("QUIC tunnel server rejected target (code %d)", e.code)
}

func (c *TunnelClient) hasQUIC() bool {
	c.quicMu.Lock()
	defer c.quicMu.Unlock()
	return c.quicConn != nil && c.quicConn.Context().Err() == nil
}

func (c *TunnelClient) warmQUIC() {
	c.quicMu.Lock()
	if c.quicWarming || (c.quicConn != nil && c.quicConn.Context().Err() == nil) {
		c.quicMu.Unlock()
		return
	}
	c.quicWarming = true
	c.quicMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), quicProbeTimeout)
		defer cancel()
		_, err := c.getQUIC(ctx)
		c.quicMu.Lock()
		c.quicWarming = false
		c.quicMu.Unlock()
		if err != nil {
			log.Printf("QUIC warm-up failed; TCP remains active: %v", err)
			return
		}
		log.Printf("QUIC warm-up complete; new proxy connections will use HTTP/3")
	}()
}

func (c *TunnelClient) scheduleWarmup() {
	c.quicMu.Lock()
	if c.quicScheduled || c.quicWarming || (c.quicConn != nil && c.quicConn.Context().Err() == nil) {
		c.quicMu.Unlock()
		return
	}
	c.quicScheduled = true
	c.quicMu.Unlock()
	delayMillis, err := randBetween(int(quicWarmupMin/time.Millisecond), int(quicWarmupMax/time.Millisecond))
	if err != nil {
		delayMillis = int(quicWarmupMin / time.Millisecond)
	}
	go func() {
		timer := time.NewTimer(time.Duration(delayMillis) * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		c.quicMu.Lock()
		c.quicScheduled = false
		c.quicMu.Unlock()
		c.warmQUIC()
	}()
}

type quicStreamConn struct {
	*quic.Stream
	connection *quic.Conn
}

func (*quicStreamConn) isQUICStream() {}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.connection.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.connection.RemoteAddr() }

func (c *TunnelClient) openQUIC(ctx context.Context, command byte, target string) (net.Conn, error) {
	connection, err := c.getQUIC(ctx)
	if err != nil {
		return nil, err
	}
	var token bytes.Buffer
	if err := writeRequest(&token, c.key, command, target, time.Now()); err != nil {
		return nil, err
	}
	requestReader, requestWriter := io.Pipe()
	streamCtx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, "https://"+c.cover.host+"/", requestReader)
	if err != nil {
		cancel()
		return nil, err
	}
	request.Host = c.cover.host
	request.Header.Set("Proxy-Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(token.Bytes()))
	responseCh := make(chan struct {
		response *http.Response
		err      error
	}, 1)
	go func() {
		response, roundTripErr := c.h3Client().RoundTrip(request)
		responseCh <- struct {
			response *http.Response
			err      error
		}{response, roundTripErr}
	}()
	var response *http.Response
	select {
	case result := <-responseCh:
		response, err = result.response, result.err
	case <-ctx.Done():
		cancel()
		_ = requestWriter.CloseWithError(context.Cause(ctx))
		return nil, context.Cause(ctx)
	}
	if err != nil {
		cancel()
		_ = requestWriter.CloseWithError(err)
		c.dropQUIC(connection)
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		cancel()
		_ = requestWriter.Close()
		_ = response.Body.Close()
		return nil, fmt.Errorf("HTTP/3 CONNECT rejected: %s", response.Status)
	}
	streamConn := &http3StreamConn{reader: response.Body, writer: requestWriter, connection: connection, cancel: cancel}
	status := []byte{0}
	if _, err := io.ReadFull(streamConn, status); err != nil {
		_ = streamConn.Close()
		return nil, err
	}
	if status[0] != 0 {
		_ = streamConn.Close()
		return nil, &tunnelRejectedError{code: status[0]}
	}
	return streamConn, nil
}

func (c *TunnelClient) h3Client() *http3.Transport {
	c.quicMu.Lock()
	defer c.quicMu.Unlock()
	if c.h3Transport == nil {
		c.h3Transport = &http3.Transport{
			TLSClientConfig: &tls.Config{ServerName: c.cover.host, NextProtos: []string{ixaQUICALPN}},
			QUICConfig:      braveClientConfig(),
			Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				return c.getQUIC(ctx)
			},
		}
	}
	return c.h3Transport
}

type http3StreamConn struct {
	reader     io.ReadCloser
	writer     *io.PipeWriter
	connection *quic.Conn
	cancel     context.CancelFunc
	closeOnce  sync.Once
}

func (*http3StreamConn) isQUICStream()                 {}
func (c *http3StreamConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *http3StreamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }
func (c *http3StreamConn) Close() error {
	c.closeOnce.Do(func() { c.cancel(); _ = c.writer.Close(); _ = c.reader.Close() })
	return nil
}
func (c *http3StreamConn) LocalAddr() net.Addr            { return c.connection.LocalAddr() }
func (c *http3StreamConn) RemoteAddr() net.Addr           { return c.connection.RemoteAddr() }
func (*http3StreamConn) SetDeadline(time.Time) error      { return nil }
func (*http3StreamConn) SetReadDeadline(time.Time) error  { return nil }
func (*http3StreamConn) SetWriteDeadline(time.Time) error { return nil }

func (c *TunnelClient) getQUIC(ctx context.Context) (*quic.Conn, error) {
	for {
		c.quicMu.Lock()
		if c.quicConn != nil && c.quicConn.Context().Err() == nil {
			connection := c.quicConn
			c.quicMu.Unlock()
			return connection, nil
		}
		if c.quicDialing {
			done := c.quicDialDone
			c.quicMu.Unlock()
			select {
			case <-done:
				c.quicMu.Lock()
				err := c.quicDialErr
				c.quicMu.Unlock()
				if err != nil {
					return nil, err
				}
				continue
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}
		staleConnection := c.quicConn
		stalePacketConn := c.quicPacketConn
		c.quicConn = nil
		c.quicPacketConn = nil
		c.quicDialing = true
		c.quicDialDone = make(chan struct{})
		c.quicDialErr = nil
		c.quicMu.Unlock()

		if staleConnection != nil {
			_ = staleConnection.CloseWithError(1, "reconnect")
		}
		if stalePacketConn != nil {
			_ = stalePacketConn.Close()
		}

		connection, packetConn, err := c.dialQUIC(ctx)
		c.quicMu.Lock()
		if err == nil {
			c.quicConn = connection
			c.quicPacketConn = packetConn
		}
		c.quicDialErr = err
		c.quicDialing = false
		close(c.quicDialDone)
		c.quicMu.Unlock()
		return connection, err
	}
}

// dialQUIC performs network and TLS work without holding quicMu. This keeps
// concurrent SOCKS requests free to take the TCP fallback while QUIC warms up.
func (c *TunnelClient) dialQUIC(ctx context.Context) (*quic.Conn, net.PacketConn, error) {
	udpAddress, err := net.ResolveUDPAddr("udp", c.config.Address())
	if err != nil {
		return nil, nil, err
	}
	packetConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, err
	}
	connection, err := quic.Dial(ctx, packetConn, udpAddress, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         c.cover.host,
		InsecureSkipVerify: true, // self-signed; hostname is checked below and peer.key authenticates the stream
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("QUIC server returned no certificate")
			}
			certificate, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			return certificate.VerifyHostname(c.cover.host)
		},
		NextProtos: []string{ixaQUICALPN},
	}, braveClientConfig())
	if err != nil {
		packetConn.Close()
		return nil, nil, err
	}
	return connection, packetConn, nil
}

func (c *TunnelClient) dropQUIC(connection *quic.Conn) {
	c.quicMu.Lock()
	defer c.quicMu.Unlock()
	if c.quicConn == connection {
		_ = c.quicConn.CloseWithError(1, "reconnect")
		if c.quicPacketConn != nil {
			_ = c.quicPacketConn.Close()
		}
		c.quicConn = nil
		c.quicPacketConn = nil
	}
}

func (s *TunnelServer) serveQUIC(ctx context.Context, packetConn *net.UDPConn) error {
	certificate, err := tempCert(s.cover.host)
	if err != nil {
		return err
	}
	transport := &quic.Transport{Conn: packetConn}
	listener, err := transport.Listen(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{ixaQUICALPN},
	}, &quic.Config{
		HandshakeIdleTimeout:           tunnelDialTimeout,
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     braveStreamWindow,
		MaxStreamReceiveWindow:         braveStreamWindow,
		InitialConnectionReceiveWindow: braveConnectionWindow,
		MaxConnectionReceiveWindow:     braveConnectionWindow,
		MaxIncomingStreams:             100,
		MaxIncomingUniStreams:          103,
		KeepAlivePeriod:                20 * time.Second,
		EnableDatagrams:                true,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer transport.Close()

	go s.serveNonQUIC(ctx, transport)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleQUIC(ctx, connection)
	}
}

func braveClientConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:                tunnelDialTimeout,
		MaxIdleTimeout:                      30 * time.Second,
		InitialStreamReceiveWindow:          braveStreamWindow,
		MaxStreamReceiveWindow:              braveStreamWindow,
		InitialConnectionReceiveWindow:      braveConnectionWindow,
		MaxConnectionReceiveWindow:          braveConnectionWindow,
		MaxIncomingStreams:                  100,
		MaxIncomingUniStreams:               103,
		KeepAlivePeriod:                     20 * time.Second,
		InitialPacketSize:                   1250,
		EnableDatagrams:                     true,
		UseChromeClientHello:                true,
		AdditionalClientTransportParameters: braveParams(),
	}
}

func braveParams() []quic.TransportParameter {
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		// A GREASE version is deliberately unusable. Falling back to a fixed
		// reserved value is therefore safe if the system RNG is unavailable.
		random = [4]byte{0x7a, 0x2a, 0x9a, 0x8a}
	}
	for i := range random {
		random[i] = random[i]&0xf0 | 0x0a
	}
	versionInformation := make([]byte, 12)
	binary.BigEndian.PutUint32(versionInformation[0:4], 1)
	copy(versionInformation[4:8], random[:])
	binary.BigEndian.PutUint32(versionInformation[8:12], 1)
	return []quic.TransportParameter{
		{ID: 0x11, Value: versionInformation},
		{ID: 0x3128, Value: []byte("ORIG")},
	}
}

func (s *TunnelServer) handleQUIC(ctx context.Context, connection *quic.Conn) {
	server := &http3.Server{Handler: http.HandlerFunc(s.handleHTTP3)}
	if err := server.ServeQUICConn(connection); err != nil && ctx.Err() == nil {
		log.Printf("HTTP/3 connection %s: %v", connection.RemoteAddr(), err)
	}
}

func (s *TunnelServer) handleHTTP3(w http.ResponseWriter, request *http.Request) {
	token, ok := parseH3Token(request.Header.Get("Proxy-Authorization"), s.key)
	if request.Method != http.MethodConnect || !ok {
		s.h3Proxy().ServeHTTP(w, request)
		return
	}
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	conn := &http3ServerConn{reader: io.MultiReader(bytes.NewReader(token), request.Body), writer: w, request: request}
	defer request.Body.Close()
	if err := s.handle(request.Context(), conn); err != nil && request.Context().Err() == nil {
		log.Printf("ixa HTTP/3 CONNECT %s: %v", request.RemoteAddr, err)
	}
}

func parseH3Token(header string, key []byte) ([]byte, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return nil, false
	}
	token, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return nil, false
	}
	_, _, err = readRequest(bytes.NewReader(token), key, time.Now())
	return token, err == nil
}

func (s *TunnelServer) h3Proxy() http.Handler {
	target := &url.URL{Scheme: "https", Host: s.cover.address}
	proxy := httputil.NewSingleHostReverseProxy(target)
	baseDirector := proxy.Director
	proxy.Director = func(request *http.Request) {
		baseDirector(request)
		request.Host = s.cover.host
		request.Header.Del("Proxy-Authorization")
	}
	proxy.Transport = &http.Transport{
		DialContext:     s.dialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.cover.host},
	}
	return proxy
}

type http3ServerConn struct {
	reader    io.Reader
	writer    io.Writer
	request   *http.Request
	flushOnce sync.Once
}

func (*http3ServerConn) isQUICStream()                {}
func (c *http3ServerConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *http3ServerConn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	// The first write is the one-byte tunnel status and must reach the client
	// before it starts relaying. Bulk payload writes should remain batchable.
	c.flushOnce.Do(func() {
		if flusher, ok := c.writer.(http.Flusher); ok {
			flusher.Flush()
		}
	})
	return n, err
}
func (*http3ServerConn) Close() error                     { return nil }
func (c *http3ServerConn) LocalAddr() net.Addr            { return http3Addr(c.request.Host) }
func (c *http3ServerConn) RemoteAddr() net.Addr           { return http3Addr(c.request.RemoteAddr) }
func (*http3ServerConn) SetDeadline(time.Time) error      { return nil }
func (*http3ServerConn) SetReadDeadline(time.Time) error  { return nil }
func (*http3ServerConn) SetWriteDeadline(time.Time) error { return nil }

type http3Addr string

func (a http3Addr) Network() string { return "udp" }
func (a http3Addr) String() string  { return string(a) }

type quicFallbackWriter struct{ transport *quic.Transport }

func (w quicFallbackWriter) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	return w.transport.WriteTo(payload, address)
}

func (s *TunnelServer) serveNonQUIC(ctx context.Context, transport *quic.Transport) {
	go s.expireUDP(ctx)
	buffer := make([]byte, maxUDPPayload)
	writer := quicFallbackWriter{transport: transport}
	for {
		n, address, err := transport.ReadNonQUICPacket(ctx, buffer)
		if err != nil {
			return
		}
		udpAddress, ok := address.(*net.UDPAddr)
		if !ok {
			continue
		}
		payload := append([]byte(nil), buffer[:n]...)
		if err := s.forwardUDP(ctx, writer, udpAddress, payload); err != nil {
			log.Printf("UDP fallback %s -> %s: %v", address, s.cover.address, err)
		}
	}
}

var _ net.Conn = (*quicStreamConn)(nil)
var _ net.Conn = (*http3StreamConn)(nil)
var _ net.Conn = (*http3ServerConn)(nil)

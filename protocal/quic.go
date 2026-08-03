package protocal

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
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

func (c *TunnelClient) hasQUICConnection() bool {
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
		_, err := c.quicConnection(ctx)
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

func (c *TunnelClient) scheduleQUICWarmup() {
	c.quicMu.Lock()
	if c.quicScheduled || c.quicWarming || (c.quicConn != nil && c.quicConn.Context().Err() == nil) {
		c.quicMu.Unlock()
		return
	}
	c.quicScheduled = true
	c.quicMu.Unlock()
	delayMillis, err := randomBetween(int(quicWarmupMin/time.Millisecond), int(quicWarmupMax/time.Millisecond))
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

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.connection.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.connection.RemoteAddr() }

func (c *TunnelClient) openQUIC(ctx context.Context, command byte, target string) (net.Conn, error) {
	connection, err := c.quicConnection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		c.dropQUIC(connection)
		return nil, err
	}
	streamConn := &quicStreamConn{Stream: stream, connection: connection}
	if deadline, ok := ctx.Deadline(); ok {
		_ = streamConn.SetDeadline(deadline)
	}
	if err := writeTunnelRequest(streamConn, c.key, command, target, time.Now()); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return nil, err
	}
	response := []byte{0}
	if _, err := io.ReadFull(streamConn, response); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return nil, err
	}
	if response[0] != 0 {
		_ = stream.Close()
		return nil, &tunnelRejectedError{code: response[0]}
	}
	_ = streamConn.SetDeadline(time.Time{})
	return streamConn, nil
}

func (c *TunnelClient) quicConnection(ctx context.Context) (*quic.Conn, error) {
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
	}, braveQUICClientConfig())
	if err != nil {
		packetConn.Close()
		return nil, nil, err
	}
	if err := initializeHTTP3Facade(ctx, connection); err != nil {
		_ = connection.CloseWithError(1, "HTTP/3 initialization failed")
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
	certificate, err := ephemeralCertificate(s.cover.host)
	if err != nil {
		return err
	}
	transport := &quic.Transport{Conn: packetConn}
	listener, err := transport.Listen(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{ixaQUICALPN},
	}, &quic.Config{
		HandshakeIdleTimeout: tunnelDialTimeout,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
	})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer transport.Close()

	go s.serveNonQUICPackets(ctx, transport)
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
		go s.handleQUICConnection(ctx, connection)
	}
}

func braveQUICClientConfig() *quic.Config {
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
		AdditionalClientTransportParameters: braveQUICTransportParameters(),
	}
}

func braveQUICTransportParameters() []quic.TransportParameter {
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

func (s *TunnelServer) handleQUICConnection(ctx context.Context, connection *quic.Conn) {
	if err := initializeHTTP3Facade(ctx, connection); err != nil {
		_ = connection.CloseWithError(1, "HTTP/3 initialization failed")
		return
	}
	for {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			conn := &quicStreamConn{Stream: stream, connection: connection}
			defer stream.Close()
			if err := s.handle(ctx, conn); err != nil && ctx.Err() == nil {
				log.Printf("ixa QUIC stream %s: %v", connection.RemoteAddr(), err)
				stream.CancelRead(1)
			}
		}()
	}
}

// initializeHTTP3Facade emits the mandatory HTTP/3 unidirectional streams.
// Proxy payload uses authenticated bidirectional streams after this standard
// HTTP/3-shaped connection preface.
func initializeHTTP3Facade(ctx context.Context, connection *quic.Conn) error {
	control, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	settings := quicvarint.Append(nil, 0)
	settings = quicvarint.Append(settings, 4)
	settingsPayload := quicvarint.Append(nil, 8)
	settingsPayload = quicvarint.Append(settingsPayload, 1)
	settings = quicvarint.Append(settings, uint64(len(settingsPayload)))
	settings = append(settings, settingsPayload...)
	if err := writeAll(control, settings); err != nil {
		return err
	}
	encoder, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if err := writeAll(encoder, quicvarint.Append(nil, 2)); err != nil {
		return err
	}
	decoder, err := connection.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if err := writeAll(decoder, quicvarint.Append(nil, 3)); err != nil {
		return err
	}
	go drainHTTP3UniStreams(connection)
	return nil
}

func drainHTTP3UniStreams(connection *quic.Conn) {
	for {
		stream, err := connection.AcceptUniStream(connection.Context())
		if err != nil {
			return
		}
		go func() { _, _ = io.Copy(io.Discard, stream) }()
	}
}

type quicFallbackWriter struct{ transport *quic.Transport }

func (w quicFallbackWriter) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	return w.transport.WriteTo(payload, address)
}

func (s *TunnelServer) serveNonQUICPackets(ctx context.Context, transport *quic.Transport) {
	go s.expireUDPSessions(ctx)
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
		if err := s.forwardUDPDatagram(ctx, writer, udpAddress, payload); err != nil {
			log.Printf("UDP fallback %s -> %s: %v", address, s.cover.address, err)
		}
	}
}

var _ net.Conn = (*quicStreamConn)(nil)

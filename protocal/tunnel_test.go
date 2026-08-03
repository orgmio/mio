package protocal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	tlsfork "github.com/refraction-networking/utls"
)

func TestTunnelRequestRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	now := time.Unix(1_800_000_000, 0)
	var packet bytes.Buffer
	if err := writeTunnelRequest(&packet, key, tunnelCommandTCP, "example.com:443", now); err != nil {
		t.Fatal(err)
	}
	command, target, err := readTunnelRequest(&packet, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if target != "example.com:443" {
		t.Fatalf("target = %q", target)
	}
	if command != tunnelCommandTCP {
		t.Fatalf("command = %d", command)
	}
}

func TestClientHelloParserPreservesPartialInput(t *testing.T) {
	inputs := [][]byte{
		[]byte("abc"),
		{22, 3, 3, 0, 10, 1, 2, 3},
	}
	for _, input := range inputs {
		preface, _, err := readClientHelloRandom(bytes.NewReader(input))
		if err == nil {
			t.Fatalf("input %x unexpectedly parsed", input)
		}
		if !bytes.Equal(preface, input) {
			t.Fatalf("preface = %x, want %x", preface, input)
		}
	}
}

func TestFallbackForwardsBytesUnchanged(t *testing.T) {
	certificate, err := ephemeralCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	server, err := newTunnelServer(
		TunnelServerConfig{Key: "93cb499ed398baa3f36f76c20483989ec911f8fe5ccd43a3c5f58952ade56435", SNI: "https://example.com:443"},
		func(cover coverTarget) (tls.Certificate, error) { return certificate, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	upstream, peer := net.Pipe()
	server.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.com:443" {
			t.Fatalf("unexpected fallback dial %s %s", network, address)
		}
		return upstream, nil
	}
	go func() {
		defer peer.Close()
		_, _ = io.Copy(peer, peer)
	}()
	client, inbound := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.serveRaw(context.Background(), inbound) }()
	payload := []byte("plain bytes that are not TLS")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("fallback changed bytes: got %x want %x", got, payload)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUDPFallbackForwardsDatagramsUnchanged(t *testing.T) {
	certificate, err := ephemeralCertificate("example.com")
	if err != nil {
		t.Fatal(err)
	}
	server, err := newTunnelServer(
		TunnelServerConfig{Key: "93cb499ed398baa3f36f76c20483989ec911f8fe5ccd43a3c5f58952ade56435", SNI: "https://example.com:443"},
		func(cover coverTarget) (tls.Certificate, error) { return certificate, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	upstream, peer := net.Pipe()
	server.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "example.com:443" {
			t.Fatalf("unexpected UDP fallback dial %s %s", network, address)
		}
		return upstream, nil
	}
	writes := make(chan udpWrite, 1)
	writer := udpCaptureWriter{writes: writes}
	client := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 45678}
	payload := []byte("QUIC datagram")
	go func() {
		got := make([]byte, len(payload))
		_, _ = io.ReadFull(peer, got)
		if !bytes.Equal(got, payload) {
			t.Errorf("upstream payload = %x, want %x", got, payload)
		}
		_, _ = peer.Write([]byte("QUIC response"))
	}()
	if err := server.forwardUDPDatagram(context.Background(), writer, client, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-writes:
		if string(got.payload) != "QUIC response" || got.address.String() != client.String() {
			t.Fatalf("UDP response = %q to %s", got.payload, got.address)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP fallback response timed out")
	}
	server.closeUDPSessions()
}

type udpWrite struct {
	payload []byte
	address *net.UDPAddr
}

type udpCaptureWriter struct {
	writes chan udpWrite
}

func (w udpCaptureWriter) WriteToUDP(payload []byte, address *net.UDPAddr) (int, error) {
	w.writes <- udpWrite{payload: append([]byte(nil), payload...), address: cloneUDPAddr(address)}
	return len(payload), nil
}

func TestUDPExchangePreservesDatagram(t *testing.T) {
	tunnelClient, tunnelServer := net.Pipe()
	upstreamServer, upstreamPeer := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- exchangeUDP(tunnelServer, upstreamServer, "dns.example:53")
	}()
	payload := []byte("udp query")
	request := binary.BigEndian.AppendUint16(nil, uint16(len(payload)))
	request = append(request, payload...)
	go func() {
		buffer := make([]byte, len(payload))
		_, _ = io.ReadFull(upstreamPeer, buffer)
		_, _ = upstreamPeer.Write([]byte("udp response"))
	}()
	if _, err := tunnelClient.Write(request); err != nil {
		t.Fatal(err)
	}
	length := make([]byte, 2)
	if _, err := io.ReadFull(tunnelClient, length); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, int(binary.BigEndian.Uint16(length)))
	if _, err := io.ReadFull(tunnelClient, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "udp response" {
		t.Fatalf("response = %q", response)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTLSAuthenticatedTunnelAndRelay(t *testing.T) {
	const keyHex = "93cb499ed398baa3f36f76c20483989ec911f8fe5ccd43a3c5f58952ade56435"
	server, err := newTunnelServer(
		TunnelServerConfig{Key: keyHex, SNI: "https://example.com:443"},
		func(cover coverTarget) (tls.Certificate, error) {
			certificate, err := ephemeralCertificate(cover.host)
			if err != nil {
				return tls.Certificate{}, err
			}
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				return tls.Certificate{}, err
			}
			certificate.PrivateKey, err = signingKeyForCertificate(leaf)
			certificate.Leaf = leaf
			return certificate, err
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	upstream, echo := net.Pipe()
	server.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.com:443" {
			t.Fatalf("unexpected dial %s %s", network, address)
		}
		return upstream, nil
	}
	go func() {
		defer echo.Close()
		_, _ = io.Copy(echo, echo)
	}()

	clientRaw, serverRaw := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- server.serveRaw(context.Background(), serverRaw)
		_ = serverRaw.Close()
	}()
	authRandom, err := makeAuthenticatedRandom(server.key, "example.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	observed := &serverHelloObserverConn{Conn: clientRaw}
	client := tlsfork.Client(observed, &tlsfork.Config{
		MinVersion:                    tlsfork.VersionTLS13,
		ServerName:                    "example.com",
		InsecureSkipVerify:            true,
		InsecureSkipCertificateVerify: true,
		NextProtos:                    []string{"http/1.1"},
		Rand:                          io.MultiReader(bytes.NewReader(authRandom), rand.Reader),
	})
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeTunnelRequest(client, server.key, tunnelCommandTCP, "example.com:443", time.Now()); err != nil {
		t.Fatal(err)
	}
	serverRandom, err := readServerHelloRandom(observed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !verifyServerAuthenticatedRandom(server.key, "example.com", authRandom, serverRandom, time.Now()) {
		t.Fatal("server HMAC authentication failed")
	}
	response := []byte{1}
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if response[0] != 0 {
		t.Fatalf("tunnel response = %d", response[0])
	}
	payload := []byte("ixa tunnel poc")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relay payload = %q", got)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel handler did not stop")
	}
}

func TestAuthenticatedClientRandom(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	now := time.Unix(1_800_000_000, 0)
	value, err := makeAuthenticatedRandom(key, "example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyAuthenticatedRandom(key, "example.com", value, now) {
		t.Fatal("valid ClientHello.Random was rejected")
	}
	if verifyAuthenticatedRandom(bytes.Repeat([]byte{0x43}, 32), "example.com", value, now) {
		t.Fatal("ClientHello.Random accepted with wrong key")
	}
	if verifyAuthenticatedRandom(key, "example.com", value, now.Add(time.Minute)) {
		t.Fatal("expired ClientHello.Random was accepted")
	}
	value[0] ^= 1
	if verifyAuthenticatedRandom(key, "example.com", value, now) {
		t.Fatal("tampered ClientHello.Random was accepted")
	}
}

func TestAuthenticatedServerRandom(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	clientRandom := bytes.Repeat([]byte{0x24}, 32)
	now := time.Unix(1_800_000_000, 0)
	value, err := makeServerAuthenticatedRandom(key, "example.com", clientRandom, now)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyServerAuthenticatedRandom(key, "example.com", clientRandom, value, now) {
		t.Fatal("valid ServerHello.Random was rejected")
	}
	wrongClientRandom := append([]byte(nil), clientRandom...)
	wrongClientRandom[0] ^= 1
	if verifyServerAuthenticatedRandom(key, "example.com", wrongClientRandom, value, now) {
		t.Fatal("ServerHello.Random accepted for a different ClientHello")
	}
	value[0] ^= 1
	if verifyServerAuthenticatedRandom(key, "example.com", clientRandom, value, now) {
		t.Fatal("tampered ServerHello.Random was accepted")
	}
}

func TestParseCoverTarget(t *testing.T) {
	tests := []struct {
		value       string
		wantHost    string
		wantAddress string
		wantErr     bool
	}{
		{value: "https://example.com:443", wantHost: "example.com", wantAddress: "example.com:443"},
		{value: "https://example.com", wantHost: "example.com", wantAddress: "example.com:443"},
		{value: "example.com", wantErr: true},
		{value: "example.com:443", wantErr: true},
		{value: "https://example.com:8443", wantHost: "example.com", wantAddress: "example.com:8443"},
		{value: "https://example.com:0", wantErr: true},
		{value: "http://example.com", wantErr: true},
		{value: "https://example.com/path", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := parseCoverTarget(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseCoverTarget error = %v, wantErr %v", err, test.wantErr)
			}
			if got.host != test.wantHost || got.address != test.wantAddress {
				t.Fatalf("parseCoverTarget = %+v, want host=%q address=%q", got, test.wantHost, test.wantAddress)
			}
		})
	}
}

func TestTunnelRequestRejectsWrongKey(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var packet bytes.Buffer
	if err := writeTunnelRequest(&packet, bytes.Repeat([]byte{1}, 32), tunnelCommandTCP, "example.com:443", now); err != nil {
		t.Fatal(err)
	}
	_, _, err := readTunnelRequest(&packet, bytes.Repeat([]byte{2}, 32), now)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected authentication failure, got %v", err)
	}
}

func TestTunnelRequestRejectsExpiredTimestamp(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	var packet bytes.Buffer
	if err := writeTunnelRequest(&packet, key, tunnelCommandTCP, "example.com:443", time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	_, _, err := readTunnelRequest(&packet, key, time.Unix(200, 0))
	if err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("expected timestamp failure, got %v", err)
	}
}

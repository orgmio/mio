package protocal

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	if err := writeTunnelRequest(&packet, key, "example.com:443", now); err != nil {
		t.Fatal(err)
	}
	target, err := readTunnelRequest(&packet, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if target != "example.com:443" {
		t.Fatalf("target = %q", target)
	}
}

func TestTLSAuthenticatedTunnelAndRelay(t *testing.T) {
	const keyHex = "93cb499ed398baa3f36f76c20483989ec911f8fe5ccd43a3c5f58952ade56435"
	server, err := NewTunnelServer(TunnelServerConfig{Key: keyHex, SNI: "https://example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately sign CertificateVerify with a key that does not match the
	// certificate. The ixa TLS fork accepts it only because peer identity is
	// verified by the ServerHello HMAC below.
	mismatchedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server.tlsConfig.Certificates[0].PrivateKey = mismatchedKey
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
	if err := writeTunnelRequest(client, server.key, "example.com:443", time.Now()); err != nil {
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
	if err := writeTunnelRequest(&packet, bytes.Repeat([]byte{1}, 32), "example.com:443", now); err != nil {
		t.Fatal(err)
	}
	_, err := readTunnelRequest(&packet, bytes.Repeat([]byte{2}, 32), now)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("expected authentication failure, got %v", err)
	}
}

func TestTunnelRequestRejectsExpiredTimestamp(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	var packet bytes.Buffer
	if err := writeTunnelRequest(&packet, key, "example.com:443", time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	_, err := readTunnelRequest(&packet, key, time.Unix(200, 0))
	if err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Fatalf("expected timestamp failure, got %v", err)
	}
}

package protocal

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"
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
	server, err := NewTunnelServer(TunnelServerConfig{Key: keyHex, SNI: "example.com"})
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
		done <- server.handle(context.Background(), tls.Server(serverRaw, server.tlsConfig))
		_ = serverRaw.Close()
	}()
	client := tls.Client(clientRaw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeTunnelRequest(client, server.key, "example.com:443", time.Now()); err != nil {
		t.Fatal(err)
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

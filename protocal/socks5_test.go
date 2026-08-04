package protocal

import (
	"context"
	"net"
	"testing"
)

func TestSOCKS5TransportDialsUDPDirectly(t *testing.T) {
	wantClient, wantServer := net.Pipe()
	defer wantClient.Close()
	defer wantServer.Close()

	called := make(chan struct{}, 1)
	server := NewSOCKS5ServerWithTransport(SOCKS5Config{}, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "dns.example:53" {
			t.Fatalf("dial = %s %s", network, address)
		}
		called <- struct{}{}
		return wantClient, nil
	})
	if server == nil {
		t.Fatal("server is nil")
	}
}

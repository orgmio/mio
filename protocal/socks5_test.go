package protocal

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5ConnectAndRelay(t *testing.T) {
	upstream, echo := net.Pipe()
	defer echo.Close()
	go func() {
		_, _ = io.Copy(echo, echo)
	}()

	client, server := net.Pipe()
	socks := NewSOCKS5Server(SOCKS5Config{})
	var dialedAddress string
	socks.dialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		dialedAddress = address
		return upstream, nil
	}
	done := make(chan error, 1)
	go func() {
		done <- socks.handle(context.Background(), server)
		_ = server.Close()
	}()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(client, authReply); err != nil {
		t.Fatal(err)
	}
	if authReply[0] != 5 || authReply[1] != 0 {
		t.Fatalf("authentication reply = %v", authReply)
	}

	request := []byte{5, 1, 0, 1, 127, 0, 0, 1}
	request = binary.BigEndian.AppendUint16(request, 8080)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("CONNECT reply code = %d", reply[1])
	}
	if dialedAddress != "127.0.0.1:8080" {
		t.Fatalf("dialed address = %q", dialedAddress)
	}

	payload := []byte("ixa socks5 poc")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}

	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS5 handler did not stop")
	}
}

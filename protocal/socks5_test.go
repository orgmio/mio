package protocal

import (
	"context"
	"io"
	"testing"
)

func TestUDPExchangeConn(t *testing.T) {
	conn := newUDPExchangeConn(context.Background(), "dns.example:53", func(_ context.Context, target string, payload []byte) ([]byte, error) {
		if target != "dns.example:53" {
			t.Fatalf("target = %q", target)
		}
		return append([]byte("response:"), payload...), nil
	})
	defer conn.Close()

	payload := []byte("query")
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		done <- err
	}()
	response := make([]byte, 64)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(response[:n]); got != "response:query" {
		t.Fatalf("response = %q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUDPExchangeConnCloseUnblocksRead(t *testing.T) {
	conn := newUDPExchangeConn(context.Background(), "dns.example:53", func(_ context.Context, _ string, _ []byte) ([]byte, error) {
		return nil, nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	_ = conn.Close()
	if err := <-done; err != nil && err != io.EOF && err != context.Canceled {
		if err.Error() != "use of closed network connection" {
			t.Fatal(err)
		}
	}
}

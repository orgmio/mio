package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "ixa.toml")
	contents := `[socks5]
listen = "127.0.0.1"
port = 1080

[peer]
server = "example.com"
port = 443
link_port = 80
key = "secret"
sni = "example.com"
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.SOCKS5.Address(), "127.0.0.1:1080"; got != want {
		t.Fatalf("address = %q, want %q", got, want)
	}
}

func TestLoadConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ixa.toml")
	if err := os.WriteFile(path, []byte("[socks5]\nlisten='127.0.0.1'\nport=1080\ntyop=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "tyop") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moaeiou/ixa-go/protocal"
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
sni = "https://example.com:443"
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

func TestConfigMode(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		want    string
		wantErr bool
	}{
		{name: "client", config: Config{Peer: protocal.PeerConfig{Server: "127.0.0.1"}}, want: "client"},
		{name: "server", config: Config{Server: protocal.TunnelServerConfig{Listen: "127.0.0.1"}}, want: "server"},
		{name: "both", config: Config{Peer: protocal.PeerConfig{Server: "peer"}, Server: protocal.TunnelServerConfig{Listen: "server"}}, wantErr: true},
		{name: "neither", config: Config{}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.config.Mode()
			if (err != nil) != test.wantErr {
				t.Fatalf("Mode error = %v, wantErr %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("Mode = %q, want %q", got, test.want)
			}
		})
	}
}

package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	mio "github.com/moaeiou/mio/protocol"
)

func TestLoadConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mio.toml")
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
		{name: "client", config: Config{Peer: mio.PeerConfig{Server: "127.0.0.1"}}, want: "client"},
		{name: "server", config: Config{Server: mio.TunnelServerConfig{Listen: "127.0.0.1"}}, want: "server"},
		{name: "both", config: Config{Peer: mio.PeerConfig{Server: "peer"}, Server: mio.TunnelServerConfig{Listen: "server"}}, wantErr: true},
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

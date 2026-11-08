package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Log    Log    `toml:"log"`
	Socks5 SOCKS5 `toml:"socks5"`
	Peer   Peer   `toml:"peer"`
}

type Log struct {
	Enable bool   `toml:"enable"`
	Level  string `toml:"level"`
	Path   string `toml:"path"`
}

type SOCKS5 struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
}

type Peer struct {
	Server   string `toml:"server"`
	Port     int    `toml:"port"`
	Dest     string `toml:"dest"`
	DestPort int    `toml:"dest_port"`
	Password string `toml:"password"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()

	cfg := Config{Log: Log{Enable: true, Level: "info"}}
	if err := toml.NewDecoder(file).Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (l Log) SlogLevel() (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(l.Level)); err != nil {
		return 0, fmt.Errorf("invalid [log].level %q: %w", l.Level, err)
	}
	return level, nil
}

func (cfg *Config) Validate() error {
	if _, err := cfg.Log.SlogLevel(); err != nil {
		return err
	}
	cfg.Socks5.Listen = strings.TrimSpace(cfg.Socks5.Listen)
	if cfg.Socks5.Listen == "" {
		return errors.New("configuration must set [socks5].listen")
	}
	if cfg.Socks5.Port < 1 || cfg.Socks5.Port > 65535 {
		return errors.New("[socks5].port must be between 1 and 65535")
	}

	peer := &cfg.Peer
	peer.Server = strings.TrimSpace(peer.Server)
	peer.Dest = strings.TrimSpace(peer.Dest)
	if peer.Server == "" {
		return errors.New("configuration must set [peer].server")
	}
	if peer.Port < 1 || peer.Port > 65535 {
		return errors.New("[peer].port must be between 1 and 65535")
	}
	if peer.Dest == "" {
		return errors.New("configuration must set [peer].dest")
	}
	if peer.DestPort < 1 || peer.DestPort > 65535 {
		return errors.New("[peer].dest_port must be between 1 and 65535")
	}
	if peer.Password == "" {
		return errors.New("configuration must set [peer].password")
	}
	return nil
}

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
	Log    LogConfig    `toml:"log"`
	Socks5 SOCKS5Config `toml:"socks5"`
	Peer   PeerConfig   `toml:"peer"`
}

type LogConfig struct {
	Enable bool   `toml:"enable"`
	Level  string `toml:"level"`
	Path   string `toml:"path"`
}

type SOCKS5Config struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
}

type PeerConfig struct {
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

	cfg := Config{Log: LogConfig{Enable: true, Level: "info"}}
	if err := toml.NewDecoder(file).Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (cfg *Config) Validate() error {
	if err := new(slog.Level).UnmarshalText([]byte(cfg.Log.Level)); err != nil {
		return fmt.Errorf("invalid [log].level %q: %w", cfg.Log.Level, err)
	}
	cfg.Socks5.Listen = strings.TrimSpace(cfg.Socks5.Listen)
	if cfg.Socks5.Listen == "" {
		return errors.New("configuration must set [socks5].listen")
	}
	if cfg.Socks5.Port < 1 || cfg.Socks5.Port > 65535 {
		return errors.New("[socks5].port must be between 1 and 65535")
	}
	return nil
}
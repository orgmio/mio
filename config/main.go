package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Socks5 SOCKS5Config `toml:"socks5"`
	Peer   PeerConfig   `toml:"peer"`
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

	var cfg Config
	if err := toml.NewDecoder(file).Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (cfg *Config) Validate() error {
	cfg.Socks5.Listen = strings.TrimSpace(cfg.Socks5.Listen)
	if cfg.Socks5.Listen == "" {
		return errors.New("configuration must set [socks5].listen")
	}
	if cfg.Socks5.Port < 1 || cfg.Socks5.Port > 65535 {
		return errors.New("[socks5].port must be between 1 and 65535")
	}
	return nil
}
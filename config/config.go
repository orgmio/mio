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
	Log       Log      `toml:"log"`
	Outbounds Outbound `toml:"outbounds"`
	Inbounds  Inbound  `toml:"inbounds"`
}

// Inbound 是服务端入站：监听地址与伪装站。
type Inbound struct {
	Listen     string `toml:"listen"`
	ListenPort int    `toml:"listen_port"`
	Dest       string `toml:"dest"`
	DestPort   int    `toml:"dest_port"`
	Password   string `toml:"password"`
}

type Log struct {
	Enable    bool   `toml:"enable"`
	Level     string `toml:"level"`
	Output    string `toml:"output"`
	Timestamp bool   `toml:"timestamp"`
}

// Outbound 是客户端出站：本地 SOCKS5 监听、mio 服务端地址与伪装站。
type Outbound struct {
	SocksListen     string `toml:"socks_listen"`
	SocksListenPort int    `toml:"socks_listen_port"`
	Server          string `toml:"server"`
	ServerPort      int    `toml:"server_port"`
	Dest            string `toml:"dest"`
	DestPort        int    `toml:"dest_port"`
	Password        string `toml:"password"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration %q: %w", path, err)
	}
	defer file.Close()

	cfg := Config{Log: Log{Enable: true, Level: "info", Timestamp: true}}
	if err := toml.NewDecoder(file).DisallowUnknownFields().Decode(&cfg); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return Config{}, fmt.Errorf("parse configuration %q: unknown field(s):\n%s", path, strict.String())
		}
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

func (cfg Config) IsServer() bool { return cfg.Inbounds.Listen != "" }

func validPort(port int) bool { return port >= 1 && port <= 65535 }

func (cfg *Config) Validate() error {
	if _, err := cfg.Log.SlogLevel(); err != nil {
		return err
	}
	cfg.Inbounds.Listen = strings.TrimSpace(cfg.Inbounds.Listen)
	if cfg.IsServer() {
		return cfg.validateServer()
	}

	out := &cfg.Outbounds
	out.SocksListen = strings.TrimSpace(out.SocksListen)
	if out.SocksListen == "" {
		return errors.New("configuration must set [outbounds].socks_listen (client) or [inbounds].listen (server)")
	}
	if !validPort(out.SocksListenPort) {
		return errors.New("[outbounds].socks_listen_port must be between 1 and 65535")
	}
	out.Server = strings.TrimSpace(out.Server)
	out.Dest = strings.TrimSpace(out.Dest)
	if out.Server == "" {
		return errors.New("configuration must set [outbounds].server")
	}
	if !validPort(out.ServerPort) {
		return errors.New("[outbounds].server_port must be between 1 and 65535")
	}
	if out.Dest == "" {
		return errors.New("configuration must set [outbounds].dest")
	}
	if !validPort(out.DestPort) {
		return errors.New("[outbounds].dest_port must be between 1 and 65535")
	}
	if out.Password == "" {
		return errors.New("configuration must set [outbounds].password")
	}
	return nil
}

func (cfg *Config) validateServer() error {
	in := &cfg.Inbounds
	in.Dest = strings.TrimSpace(in.Dest)
	if !validPort(in.ListenPort) {
		return errors.New("[inbounds].listen_port must be between 1 and 65535")
	}
	if in.Dest == "" {
		return errors.New("configuration must set [inbounds].dest")
	}
	if !validPort(in.DestPort) {
		return errors.New("[inbounds].dest_port must be between 1 and 65535")
	}
	if in.Password == "" {
		return errors.New("configuration must set [inbounds].password")
	}
	return nil
}

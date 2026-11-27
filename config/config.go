package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/orgmio/mio/protocol"
)

type Config struct {
	Log       Log       `toml:"log"`
	Outbounds *Outbound `toml:"outbounds"`
	Inbounds  *Inbound  `toml:"inbounds"`
}

// Transport 指定 mio 客户端与服务端之间使用的传输。零值表示自动选路。
type Transport string

const (
	TransportAuto Transport = ""
	TransportTCP  Transport = "tcp"
	TransportUDP  Transport = "udp"
)

func (t *Transport) normalize(section string) error {
	switch *t {
	case "auto":
		*t = TransportAuto
	case TransportAuto, TransportTCP, TransportUDP:
	default:
		return fmt.Errorf("invalid [%s].transport %q (want auto, tcp or udp)", section, *t)
	}
	return nil
}

// Inbound 是服务端入站：监听地址与伪装站。
type Inbound struct {
	Listen     string    `toml:"listen"`
	ListenPort int       `toml:"listen_port"`
	Dest       string    `toml:"dest"`
	DestPort   int       `toml:"dest_port"` // 选填，0 表示与 ListenPort 相同
	PrivateKey string    `toml:"private_key"`
	Transport  Transport `toml:"transport"`
}

type Log struct {
	Enable    bool   `toml:"enable"`
	Level     string `toml:"level"`
	Output    string `toml:"output"`
	Timestamp bool   `toml:"timestamp"`
}

// Outbound 是客户端出站：本地 SOCKS5 监听、mio 服务端地址与伪装站。
type Outbound struct {
	SocksListen     string    `toml:"socks_listen"`
	SocksListenPort int       `toml:"socks_listen_port"`
	Socks5UDP       bool      `toml:"socks5_udp"`
	Server          string    `toml:"server"`
	ServerPort      int       `toml:"server_port"`
	Dest            string    `toml:"dest"`
	PublicKey       string    `toml:"public_key"`
	Transport       Transport `toml:"transport"`
}

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config at %s: %w", path, err)
	}
	defer file.Close()

	cfg := Config{Log: Log{Enable: true, Level: "info"}}
	if err := toml.NewDecoder(file).DisallowUnknownFields().Decode(&cfg); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			// TOML 的上下文摘录可能包含相邻的密钥，只报告字段位置和名称。
			var fields []error
			for _, field := range strict.Errors {
				line, column := field.Position()
				fields = append(fields, fmt.Errorf("%s:%d:%d: unknown field %q", path, line, column, strings.Join(field.Key(), ".")))
			}
			return Config{}, errors.Join(fields...)
		}
		return Config{}, fmt.Errorf("decode config at %s: %w", path, err)
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

// HasServer 表示配置了 [inbounds]，需要启动服务端。
func (cfg Config) HasServer() bool { return cfg.Inbounds != nil }

// HasClient 表示配置了 [outbounds]，需要启动客户端。
func (cfg Config) HasClient() bool { return cfg.Outbounds != nil }

func validPort(port int) bool { return port >= 1 && port <= 65535 }

// Validate 检查配置：[inbounds] 和 [outbounds] 至少要有一个，两个都有则同时启动服务端和客户端。
func (cfg *Config) Validate() error {
	if _, err := cfg.Log.SlogLevel(); err != nil {
		return err
	}
	if !cfg.HasServer() && !cfg.HasClient() {
		return errors.New("configuration must set [outbounds] (client), [inbounds] (server), or both")
	}
	if cfg.HasServer() {
		if err := cfg.validateServer(); err != nil {
			return err
		}
	}
	if cfg.HasClient() {
		return cfg.validateClient()
	}
	return nil
}

func (cfg *Config) validateClient() error {
	out := cfg.Outbounds
	if err := out.Transport.normalize("outbounds"); err != nil {
		return err
	}
	out.SocksListen = strings.TrimSpace(out.SocksListen)
	if out.SocksListen == "" {
		return errors.New("configuration must set [outbounds].socks_listen")
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
	if out.PublicKey == "" {
		return errors.New("configuration must set [outbounds].public_key (run `mio keygen`)")
	}
	if _, err := protocol.ParsePublicKey(out.PublicKey); err != nil {
		return fmt.Errorf("[outbounds].public_key: %w", err)
	}
	return nil
}

func (cfg *Config) validateServer() error {
	in := cfg.Inbounds
	if err := in.Transport.normalize("inbounds"); err != nil {
		return err
	}
	in.Listen = strings.TrimSpace(in.Listen)
	in.Dest = strings.TrimSpace(in.Dest)
	if in.Listen == "" {
		return errors.New("configuration must set [inbounds].listen")
	}
	if !validPort(in.ListenPort) {
		return errors.New("[inbounds].listen_port must be between 1 and 65535")
	}
	if in.Dest == "" {
		return errors.New("configuration must set [inbounds].dest")
	}
	if in.DestPort != 0 && !validPort(in.DestPort) {
		return errors.New("[inbounds].dest_port must be between 1 and 65535 (or omitted to use listen_port)")
	}
	if in.PrivateKey == "" {
		return errors.New("configuration must set [inbounds].private_key (run `mio keygen`)")
	}
	if _, err := protocol.ParsePrivateKey(in.PrivateKey); err != nil {
		return fmt.Errorf("[inbounds].private_key: %w", err)
	}
	return nil
}

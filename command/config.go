package command

import (
	"errors"
	"fmt"
	"os"

	mio "github.com/moaeiou/mio/protocol"
	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	SOCKS5 mio.SOCKS5Config       `toml:"socks5"`
	Peer   mio.PeerConfig         `toml:"peer"`
	Server mio.TunnelServerConfig `toml:"server"`
}

func (c Config) Mode() (string, error) {
	hasPeer := c.Peer.Server != "" || c.Peer.Port != 0 || c.Peer.Key != "" || c.Peer.SNI != ""
	hasServer := c.Server.Listen != "" || c.Server.Port != 0 || c.Server.Key != "" || c.Server.SNI != ""
	switch {
	case hasPeer && hasServer:
		return "", fmt.Errorf("peer and server cannot exist in the same configuration")
	case hasServer:
		return "server", nil
	case hasPeer:
		return "client", nil
	default:
		return "", fmt.Errorf("configuration must contain either peer or server")
	}
}

func LoadConfig(path string) (Config, error) {
	var cfg Config
	file, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer file.Close()
	decoder := toml.NewDecoder(file).DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		var strictError *toml.StrictMissingError
		if errors.As(err, &strictError) {
			return cfg, fmt.Errorf("unknown configuration field:\n%s", strictError.String())
		}
		return cfg, err
	}
	return cfg, nil
}

func (c Config) ValidateClient() error {
	if c.SOCKS5.Listen == "" {
		return fmt.Errorf("socks5.listen must not be empty")
	}
	if err := validPort("socks5.port", c.SOCKS5.Port); err != nil {
		return err
	}
	if c.Peer.Server == "" {
		return fmt.Errorf("peer.server must not be empty")
	}
	if err := validPort("peer.port", c.Peer.Port); err != nil {
		return err
	}
	if c.Peer.SNI == "" {
		return fmt.Errorf("peer.sni must not be empty")
	}
	return nil
}

func (c Config) ValidateServer() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen must not be empty")
	}
	if err := validPort("server.port", c.Server.Port); err != nil {
		return err
	}
	if c.Server.SNI == "" {
		return fmt.Errorf("server.sni must not be empty")
	}
	return nil
}

func validPort(name string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s must be between 1 and 65535", name)
	}
	return nil
}

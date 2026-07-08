package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config 是整个 config.toml 反序列化后的顶层结构。
type Config struct {
	Socks5 Socks5Config `toml:"socks5"`
	Peer   PeerConfig   `toml:"peer"`
	Server ServerConfig `toml:"server"`
}

type Socks5Config struct {
	Listen string `toml:"listen"`
	Port   int    `toml:"port"`
}

// PeerConfig 描述客户端角色：本机作为 ixa 客户端时，要连接的远端服务器信息。
type PeerConfig struct {
	Server   string `toml:"server"`
	Port     int    `toml:"port"`
	LinkPort int    `toml:"link_port"`
	KeyHex   string `toml:"key"`
	SNI      string `toml:"sni"`
}

// ServerConfig 描述服务端角色配置。
type ServerConfig struct {
	Listen   string `toml:"listen"`
	Port     int    `toml:"port"`
	LinkPort int    `toml:"link_port"`
	KeyHex   string `toml:"key"`
	SNI      string `toml:"sni"`
}

// LoadConfig 从指定路径读取并解析 TOML 配置文件。
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}
	return &cfg, nil
}

// PeerKey 返回 peer.key 解码后的原始字节。
func (p PeerConfig) PeerKey() ([]byte, error) {
	key, err := hex.DecodeString(p.KeyHex)
	if err != nil {
		return nil, fmt.Errorf("peer.key is not valid hex: %w", err)
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("peer.key too short (%d bytes), see README for recommended lengths", len(key))
	}
	return key, nil
}

// ServerKey 返回 server.key 解码后的原始字节。
func (s ServerConfig) ServerKey() ([]byte, error) {
	key, err := hex.DecodeString(s.KeyHex)
	if err != nil {
		return nil, fmt.Errorf("server.key is not valid hex: %w", err)
	}
	if len(key) < 16 {
		return nil, fmt.Errorf("server.key too short (%d bytes), see README for recommended lengths", len(key))
	}
	return key, nil
}

// HasPeer 判断配置文件是否填写了 [peer] 段（用于 main.go 决定是否启动客户端角色）。
func (c *Config) HasPeer() bool {
	return c.Peer.Server != "" && c.Peer.SNI != ""
}

// HasServer 判断配置文件是否填写了 [server] 段（用于 main.go 决定是否启动服务端角色）。
func (c *Config) HasServer() bool {
	return c.Server.Listen != "" && c.Server.SNI != ""
}

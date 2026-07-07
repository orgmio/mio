package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/things-go/go-socks5"
)

type Config struct {
	Socks5 struct {
		Listen string `toml:"listen"`
		Port   int    `toml:"port"`
	} `toml:"socks5"`
}

type LoggingRule struct {
}

func main() {
	configPath := flag.String("c", "", "Config file path")
	flag.Parse()

	if *configPath == "" {
		fmt.Println("Not have any parameter, minimal using ./ixa -c config_file_path")
		os.Exit(1)
	}

	fileData, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Printf("Cannot read config file %v\n", err)
		os.Exit(1)
	}

	var cfg Config
	if err := toml.Unmarshal(fileData, &cfg); err != nil {
		fmt.Printf("Cannot decode config file %v\n", err)
		os.Exit(1)
	}

	addr := net.JoinHostPort(cfg.Socks5.Listen, fmt.Sprintf("%d", cfg.Socks5.Port))
	server := socks5.NewServer()

	fmt.Printf("SOCKS5 server listening on %s\n", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil {
		fmt.Printf("Server failed: %v\n", err)
		os.Exit(1)
	}
}

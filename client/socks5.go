package client

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"strconv"

	"github.com/orgmio/mio/config"
	"github.com/things-go/go-socks5"
)

type SOCKS5Node struct {
	config config.SOCKS5Config
	server *socks5.Server
}

func NewSOCKS5(cfg config.SOCKS5Config) *SOCKS5Node {
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.Default())),
	)
	return &SOCKS5Node{config: cfg, server: server}
}

func (node *SOCKS5Node) Run() error {
	address := net.JoinHostPort(node.config.Listen, strconv.Itoa(node.config.Port))
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}

	slog.Info("Listen Socks5 successfully at port " + strconv.Itoa(node.config.Port), "address", listener.Addr().String())
	return node.server.Serve(listener)
}
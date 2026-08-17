package command

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	mio "github.com/orgmio/mio/protocol"
)

func Run(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		PrintVersion()
		return nil
	}

	explicitMode := ""
	if len(args) > 0 && (args[0] == "client" || args[0] == "server") {
		explicitMode = args[0]
		args = args[1:]
	}
	flags := flag.NewFlagSet("mio", flag.ContinueOnError)
	configPath := "config.toml"
	flags.StringVar(&configPath, "c", configPath, "path to the TOML configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	mode, err := cfg.Mode()
	if err != nil {
		return err
	}
	if explicitMode != "" && explicitMode != mode {
		return fmt.Errorf("%s command cannot use a %s configuration", explicitMode, mode)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if mode == "server" {
		if err := cfg.ValidateServer(); err != nil {
			return fmt.Errorf("server config: %w", err)
		}
		server, err := mio.NewTunnelServer(cfg.Server)
		if err != nil {
			return fmt.Errorf("create mio server: %w", err)
		}
		log.Printf("mio server listening on %s", cfg.Server.Address())
		if err := server.ListenAndServe(ctx); err != nil {
			return fmt.Errorf("serve mio tunnel: %w", err)
		}
		return nil
	}

	if err := cfg.ValidateClient(); err != nil {
		return fmt.Errorf("client config: %w", err)
	}
	tunnel, err := mio.NewTunnelClient(cfg.Peer)
	if err != nil {
		return fmt.Errorf("create mio client: %w", err)
	}
	tunnel.StartCover()
	server := mio.NewSOCKS5Server(cfg.SOCKS5, tunnel.DialContext)
	log.Printf("SOCKS5 listening on %s", cfg.SOCKS5.Address())
	log.Printf("mio peer %s", cfg.Peer.Address())
	if err := server.ListenAndServe(ctx); err != nil {
		return fmt.Errorf("serve SOCKS5: %w", err)
	}
	return nil
}

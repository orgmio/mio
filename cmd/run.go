package cmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/orgmio/mio/client"
	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/server"
)

func Run(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var configPath string
	flags.StringVar(&configPath, "c", "", "configuration file path")
	flags.StringVar(&configPath, "config", "", "configuration file path")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: mio run -c <config.toml>")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flags.Arg(0))
	}
	if configPath == "" {
		return errors.New("missing configuration file; use -c <path>")
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	closeLog, err := setupLog(cfg.Log)
	if err != nil {
		return err
	}
	defer closeLog()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.IsServer() {
		srv, err := server.New(cfg.Inbounds)
		if err != nil {
			return err
		}
		return srv.Run(ctx)
	}
	node, err := client.NewSOCKS5(cfg.Outbounds)
	if err != nil {
		return err
	}
	return node.Run(ctx)
}

func setupLog(cfg config.Log) (func(), error) {
	if !cfg.Enable {
		slog.SetDefault(slog.New(slog.DiscardHandler))
		return func() {}, nil
	}

	level, err := cfg.SlogLevel()
	if err != nil {
		return nil, err
	}

	var output io.Writer = os.Stderr
	closeLog := func() {}
	if cfg.Output != "" {
		file, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open log file %q: %w", cfg.Output, err)
		}
		output = file
		closeLog = func() { file.Close() }
	}

	options := &slog.HandlerOptions{Level: level}
	if !cfg.Timestamp {
		options.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(output, options)))
	return closeLog, nil
}

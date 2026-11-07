package command

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/orgmio/mio/client"
	"github.com/orgmio/mio/config"
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
	return client.NewSOCKS5(cfg.Socks5).Run()
}
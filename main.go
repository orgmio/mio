package main

import (
	"log/slog"
	"os"

	"github.com/orgmio/mio/command"
)

func main() {
	logger := slog.New(
		slog.NewTextHandler(
			os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			},
		),
	)
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		command.Help()
		return
	}

	switch os.Args[1] {
	case "run":
		if err := command.Run(os.Args[2:]); err != nil {
			logger.Error("Failed to start : ", "err", err)
			os.Exit(1)
		}
	case "version":
		command.PrintVersion()
	case "help":
		command.Help()
	default:
		command.Help()
	}
}

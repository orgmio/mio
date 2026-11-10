package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/orgmio/mio/common"
)

func main() {
	logger := slog.New(
		slog.NewTextHandler(
			os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelInfo,
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
			logger.Error("Failed to run : ", "err", err)
			os.Exit(1)
		}
	case "version":
		command.PrintVersion()
	case "help":
		command.Help()
	default:
		msg := fmt.Sprintf("unknown command %q for \"mio\"", os.Args[1])
		fmt.Fprintf(os.Stderr, "Error: %s\nRun 'mio help' for usage.\n", msg)
		os.Exit(1)
	}
}

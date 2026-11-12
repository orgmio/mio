// Package cmd 是 mio 命令行程序：解析子命令、读取配置并启动客户端或服务端。
package cmd

import (
	"fmt"
	"log/slog"
	"os"
)

// Execute 按 os.Args 执行对应的子命令。
func Execute() {
	logger := slog.New(
		slog.NewTextHandler(
			os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			},
		),
	)
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		Help()
		return
	}

	switch os.Args[1] {
	case "run":
		if err := Run(os.Args[2:]); err != nil {
			logger.Error("Failed to run : ", "err", err)
			os.Exit(1)
		}
	case "version":
		PrintVersion()
	case "help":
		Help()
	default:
		msg := fmt.Sprintf("unknown command %q for \"mio\"", os.Args[1])
		fmt.Fprintf(os.Stderr, "Error: %s\nRun 'mio help' for usage.\n", msg)
		os.Exit(1)
	}
}

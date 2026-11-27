package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/orgmio/mio/client"
	"github.com/orgmio/mio/config"
	"github.com/orgmio/mio/server"
)

// service 是服务端或客户端：Start 开始监听，Serve 处理连接直到 ctx 结束。
type service interface {
	Start(ctx context.Context) error
	Serve(ctx context.Context) error
	Close()
}

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run service",
	Args:  cobra.NoArgs,
	Run: func(*cobra.Command, []string) {
		if err := Run(configPath); err != nil {
			fatal(err)
		}
	},
}

func init() {
	mainCommand.AddCommand(commandRun)
}

// Run 读取 configPath 指向的配置文件并启动其中配置的客户端和/或服务端，直到收到退出信号。
// configPath 为空时读取当前目录下的 config.toml。
func Run(configPath string) error {
	if configPath == "" {
		configPath = defaultConfigPath
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
	// 配置了 [inbounds] 就启动服务端，配置了 [outbounds] 就启动客户端，两个都有则同时运行。
	var services []service
	if cfg.HasServer() {
		srv, err := server.New(*cfg.Inbounds)
		if err != nil {
			return err
		}
		services = append(services, srv)
	}
	if cfg.HasClient() {
		node, err := client.NewSOCKS5(*cfg.Outbounds)
		if err != nil {
			return err
		}
		services = append(services, node)
	}

	// 任何一个退出（出错或收到信号）都会让另一个一起停下，返回最先出现的错误。
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i, s := range services {
		if err := s.Start(ctx); err != nil {
			cancel()
			for _, started := range slices.Backward(services[:i]) {
				started.Close()
			}
			return err
		}
	}
	slog.Info(fmt.Sprintf("mio started (%.2fs)", time.Since(startTime).Seconds()))

	results := make(chan error, len(services))
	for _, s := range services {
		go func() { results <- s.Serve(ctx) }()
	}
	var firstErr error
	for range services {
		if err := <-results; err != nil && firstErr == nil {
			firstErr = err
		}
		cancel()
	}
	return firstErr
}

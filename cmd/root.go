// Package cmd 是 mio 命令行程序：解析子命令、读取配置并启动客户端和/或服务端。
package cmd

import (
	"github.com/spf13/cobra"
)

// defaultConfigPath 是没有用 -c 指定配置文件时读取的路径，相对当前工作目录。
const defaultConfigPath = "config.toml"

var (
	configPath   string
	disableColor bool
)

var mainCommand = &cobra.Command{
	Use: "mio",
	PersistentPreRun: func(*cobra.Command, []string) {
		useConsoleLog()
	},
}

func init() {
	mainCommand.PersistentFlags().StringVarP(&configPath, "config", "c", "", "set configuration file path")
	mainCommand.PersistentFlags().BoolVarP(&disableColor, "disable-color", "", false, "disable color output")
}

// Execute 按 os.Args 执行对应的子命令。
func Execute() {
	if err := mainCommand.Execute(); err != nil {
		fatal(err)
	}
}

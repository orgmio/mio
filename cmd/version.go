package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/orgmio/mio/protocol"
)

// 这里是 mio 的程序版本。

const Version = "0.5.8"

var nameOnly bool

var commandVersion = &cobra.Command{
	Use:   "version",
	Short: "Print current version of mio",
	Args:  cobra.NoArgs,
	Run: func(*cobra.Command, []string) {
		if nameOnly {
			fmt.Println(Version)
			return
		}
		PrintVersion()
	},
}

func init() {
	commandVersion.Flags().BoolVarP(&nameOnly, "name", "n", false, "print version name only")
	mainCommand.AddCommand(commandVersion)
}

// PrintVersion 打印程序版本、协议版本和构建信息。
func PrintVersion() {
	fmt.Println("The mio Proxy Protocol")
	fmt.Println("Binary version " + Version)
	fmt.Println("Protocol version: " + protocol.Version)
	fmt.Println()
	settings := make(map[string]string)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			settings[s.Key] = s.Value
		}
	}
	fmt.Println("Environment: " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH)
	fmt.Println("Revision: " + settings["vcs.revision"])
	cgo := "disabled"
	if settings["CGO_ENABLED"] == "1" {
		cgo = "enabled"
	}
	fmt.Println("CGO_ENABLED: " + cgo)
}

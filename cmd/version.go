package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/orgmio/mio/protocol"
)
// 该程序仅用于输出版本号，提升版本号请更改mio/protocol/version.go的值
func PrintVersion() {
	fmt.Println("The MIO proxy protocol V" + protocol.Version)
	fmt.Println()
	settings := make(map[string]string)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			settings[s.Key] = s.Value
		}
	}
	fmt.Println("Environment=" + runtime.Version() + " " + runtime.GOARCH)
	fmt.Println("Commit Hash=" + settings["vcs.revision"])
	fmt.Println("CGO_Enabled=" + settings["CGO_ENABLED"])
}

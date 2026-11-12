package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

const Version = "0.5.0"

func PrintVersion() {
	fmt.Println("The MIO proxy protocol V" + Version)
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

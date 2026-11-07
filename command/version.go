package command

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

const Version = "0.4.2"

func PrintVersion() {
	fmt.Println("The MIO proxy protocol V" + Version + "\n")
	info, _ := debug.ReadBuildInfo()
	settings := make(map[string]string)
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	fmt.Println("Environment=" + runtime.Version() + " " + runtime.GOARCH)
	fmt.Println("Commit Hash=" + settings["vcs.revision"])
	fmt.Println("CGO_Enabled=" + settings["CGO_ENABLED"])
}

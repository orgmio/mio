package command

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

const Version = "0.4.1"

func PrintVersion() {
	fmt.Printf("The MIO proxy protocol V%s\n\n", Version)
	info, _ := debug.ReadBuildInfo()
	settings := make(map[string]string)
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	fmt.Printf("Environment=%s %s\n", runtime.Version(), runtime.GOARCH)
	fmt.Printf("Commit Hash=%s\n", settings["vcs.revision"])
	fmt.Printf("CGO_Enabled=%s\n", settings["CGO_ENABLED"])
}

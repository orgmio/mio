package command

import (
	"fmt"
	"os"
	"runtime/debug"
)

const Version = "0.1.6"

func PrintVersion() {
	fmt.Printf("ixa-go V%s\n\n", Version)
	info, _ := debug.ReadBuildInfo()
	settings := make(map[string]string)
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	fmt.Printf("Golang Version=%s\n", info.GoVersion)
	fmt.Printf("Commit=%s\n", settings["vcs.revision"])
	fmt.Printf("CGO_Enabled=%s\n", settings["CGO_ENABLED"])
	os.Exit(0)
}

package cmd

import (
	"fmt"
)

func Help() {
	fmt.Println("Usage:")
	fmt.Println("  mio [command]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  run       Run SOCKS5 service")
	fmt.Println("  version   Print current version of MIO")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -c, --config string             set configuration file path")
}

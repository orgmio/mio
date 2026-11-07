package command

import (
	"fmt"
)

func Help(){
	fmt.Println("The MIO Proxy Protocol")
	fmt.Println("Usage:")
	fmt.Printf("  mio [command]\n\n")
    fmt.Println("Avaliable Commands:")
	fmt.Println("  run       Run service")
	fmt.Println("  check     Check configuration")
	fmt.Println("  format    Format configuration")
	fmt.Printf("  version   Print current version of MIO\n\n")
	fmt.Println("Flags:")
    fmt.Println("  -c, --config stringArray             set configuration file path")
	fmt.Printf("  -h, --help                           help for sing-box\n\n")
	fmt.Println("Use 'mio [command] --help' for more information about a command.")
}
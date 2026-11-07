package command

import (
	"fmt"
)

func Help() {
	fmt.Println("Usage:")
	fmt.Println("  mio [command]\n")
	fmt.Println("Avaliable Commands:")
	fmt.Println("  run       Run service")
	fmt.Println("  check     Check configuration")
	fmt.Println("  format    Format configuration")
	fmt.Println("  version   Print current version of MIO\n")
	fmt.Println("Flags:")
	fmt.Println("  -c, --config stringArray             set configuration file path")
	fmt.Println("  -h, --help                           help for mio")
}

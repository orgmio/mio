package main

import (
	"log"
	"os"

	"github.com/moaeiou/ixa-go/command"
)

func main() {
	if err := command.Run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

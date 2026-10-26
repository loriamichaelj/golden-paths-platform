// Command gold checks and explains golden-path contracts.
package main

import (
	"os"
	"time"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/app"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	a := &app.App{Out: os.Stdout, Err: os.Stderr, Now: time.Now, Getenv: os.Getenv, Version: version}
	os.Exit(a.Run(os.Args[1:]))
}

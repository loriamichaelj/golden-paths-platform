// Command release builds and publishes gold release archives for the pipeline.
package main

import (
	"os"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/release"
)

func main() {
	os.Exit(release.Run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

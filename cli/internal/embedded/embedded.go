// Package embedded carries a copy of golden-paths/ inside the gold binary, so
// the CLI and the data it checks against are always the same version.
// "make sync" refreshes the copy; "make check-sync" fails when it has drifted.
package embedded

import (
	"embed"
	"io/fs"
)

//go:embed golden-paths
var files embed.FS

// FS returns the embedded golden-paths/ tree.
func FS() fs.FS {
	sub, err := fs.Sub(files, "golden-paths")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	return sub
}

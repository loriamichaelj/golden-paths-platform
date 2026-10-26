package release

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

const usage = `release builds and publishes gold release archives.

Usage:
  release version-from-tag --prefix gold-v --tag gold-v1.2.3
  release build --version 1.2.3 --out dist [--module .] [--targets linux/amd64,darwin/arm64]
  release verify --dir dist
  release upload --dir dist --package gold --version 1.2.3

upload reads CI_API_V4_URL, CI_PROJECT_ID and CI_JOB_TOKEN from the environment.
`

// Run executes one command and returns the exit status: 0 success, 1 a failed
// check or build, 2 a usage problem.
func Run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("release "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "release: "+format+"\n", a...)
		return code
	}

	switch args[0] {
	case "version-from-tag":
		prefix := fs.String("prefix", "", "tag prefix, such as gold-v")
		tag := fs.String("tag", "", "the release tag")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		v, err := VersionFromTag(*prefix, *tag)
		if err != nil {
			return fail(1, "%v", err)
		}
		fmt.Fprintln(stdout, v)
	case "build":
		version := fs.String("version", "", "version to stamp, such as 1.2.3")
		out := fs.String("out", "dist", "folder for the archives")
		module := fs.String("module", ".", "folder holding go.mod")
		targets := fs.String("targets", "", "comma-separated os/arch list (default: all six)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *version == "" {
			return fail(2, "build needs --version")
		}
		opts := BuildOptions{ModuleDir: *module, Version: *version, Out: *out}
		if *targets != "" {
			t, err := ParseTargets(*targets)
			if err != nil {
				return fail(2, "%v", err)
			}
			opts.Targets = t
		}
		names, err := Build(opts)
		if err != nil {
			return fail(1, "%v", err)
		}
		fmt.Fprintf(stdout, "built %d archives in %s: %s\n", len(names), *out, strings.Join(names, " "))
	case "verify":
		dir := fs.String("dir", "dist", "folder holding the archives and checksums.txt")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := VerifyChecksums(*dir); err != nil {
			return fail(1, "%v", err)
		}
		fmt.Fprintf(stdout, "checksums verified in %s\n", *dir)
	case "upload":
		dir := fs.String("dir", "dist", "folder to upload")
		pkg := fs.String("package", "gold", "package name")
		version := fs.String("version", "", "package version")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if *version == "" {
			return fail(2, "upload needs --version")
		}
		u := Uploader{BaseURL: getenv("CI_API_V4_URL"), ProjectID: getenv("CI_PROJECT_ID"), Token: getenv("CI_JOB_TOKEN")}
		sent, err := u.Upload(*pkg, *version, *dir)
		if err != nil {
			return fail(1, "%v", err)
		}
		fmt.Fprintf(stdout, "uploaded %d files to package %s %s\n", len(sent), *pkg, *version)
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "release: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	return 0
}

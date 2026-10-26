// Package app implements the gold command line.
package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/embedded"
	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/golden"
)

// Exit codes: findings are a normal outcome; usage and I/O problems are not.
const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

// App is one run of the CLI with its inputs and outputs made explicit.
type App struct {
	Out, Err io.Writer
	Now      func() time.Time
	Getenv   func(string) string
	Version  string
}

const usage = `gold checks and explains golden-path contracts.

Usage:
  gold validate [--strict] [--format text|json] [path...]
  gold explain [--format text|json] [path]
  gold init --archetype <type> --cloud <cloud> --name <app> --owner <team> [--out file] [--force]
  gold catalog list|show <archetype>|modules|schema [--format text|json]
  gold version

A path is a golden-path.yaml file or a folder that holds one; the default is
./golden-path.yaml. Exit status is 0 when everything is fine, 1 when a contract
has errors (or warnings with --strict), and 2 for usage or file problems.
`

// Run executes one command and returns the exit status.
func (a *App) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.Err, usage)
		return exitUsage
	}
	switch args[0] {
	case "validate":
		return a.validate(args[1:])
	case "explain":
		return a.explain(args[1:])
	case "init":
		return a.initCmd(args[1:])
	case "catalog":
		return a.catalog(args[1:])
	case "version", "--version":
		fmt.Fprintf(a.Out, "gold %s\n", a.Version)
		return exitOK
	case "help", "--help", "-h":
		fmt.Fprint(a.Out, usage)
		return exitOK
	}
	fmt.Fprintf(a.Err, "gold: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func (a *App) platform() (*golden.Platform, error) {
	if dir := a.Getenv("GOLD_GOLDEN_PATHS_DIR"); dir != "" {
		return golden.Load(os.DirFS(dir))
	}
	return golden.Load(embedded.FS())
}

func (a *App) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("gold "+name, flag.ContinueOnError)
	fs.SetOutput(a.Err)
	return fs
}

// parse accepts flags before, between and after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func (a *App) fail(code int, format string, args ...any) int {
	fmt.Fprintf(a.Err, "gold: "+format+"\n", args...)
	return code
}

func (a *App) usageErr(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	return exitUsage
}

func (a *App) writeJSON(v any) {
	enc := json.NewEncoder(a.Out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func contractPath(path string) string {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return filepath.Join(path, "golden-path.yaml")
	}
	return path
}

func checkFormat(format string) bool { return format == "text" || format == "json" }

func (a *App) validate(args []string) int {
	fs := a.flags("validate")
	strict := fs.Bool("strict", false, "treat warnings as errors")
	format := fs.String("format", "text", "text or json")
	paths, err := parse(fs, args)
	if err != nil {
		return a.usageErr(err)
	}
	if !checkFormat(*format) {
		return a.fail(exitUsage, "--format must be text or json")
	}
	if len(paths) == 0 {
		paths = []string{"golden-path.yaml"}
	}
	p, err := a.platform()
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}

	status := exitOK
	var results []golden.Result
	for _, path := range paths {
		file := contractPath(path)
		data, err := os.ReadFile(file)
		if err != nil {
			a.fail(exitUsage, "%v", err)
			status = exitUsage
			continue
		}
		res := p.Validate(file, data, *strict, a.Now())
		results = append(results, res)
		if !res.Valid && status == exitOK {
			status = exitFindings
		}
	}

	if *format == "json" {
		a.writeJSON(map[string]any{"valid": status == exitOK, "files": results})
		return status
	}
	for _, res := range results {
		a.printResult(res)
	}
	return status
}

func (a *App) printResult(res golden.Result) {
	warnings := 0
	for _, f := range res.Findings {
		if f.Severity == "warning" {
			warnings++
		}
		where := res.Path
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", res.Path, f.Line)
		}
		if f.Path != "" {
			fmt.Fprintf(a.Out, "%s: %s: %s: %s\n", where, f.Severity, f.Path, f.Message)
		} else {
			fmt.Fprintf(a.Out, "%s: %s: %s\n", where, f.Severity, f.Message)
		}
	}
	if res.Valid {
		note := ""
		if warnings > 0 {
			note = fmt.Sprintf(" (%d warning(s))", warnings)
		}
		fmt.Fprintf(a.Out, "ok  %s%s\n", res.Path, note)
	}
}

func (a *App) explain(args []string) int {
	fs := a.flags("explain")
	format := fs.String("format", "text", "text or json")
	paths, err := parse(fs, args)
	if err != nil {
		return a.usageErr(err)
	}
	if !checkFormat(*format) {
		return a.fail(exitUsage, "--format must be text or json")
	}
	if len(paths) > 1 {
		return a.fail(exitUsage, "explain takes one contract")
	}
	path := "golden-path.yaml"
	if len(paths) == 1 {
		path = paths[0]
	}
	p, err := a.platform()
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	file := contractPath(path)
	data, err := os.ReadFile(file)
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	res := p.Validate(file, data, false, a.Now())
	if !res.Valid {
		a.printResult(res)
		fmt.Fprintln(a.Err, "gold: fix these errors before explaining the contract")
		return exitFindings
	}
	ex := p.Explain(res.Contract)
	if *format == "json" {
		a.writeJSON(ex)
	} else {
		ex.WriteText(a.Out)
	}
	return exitOK
}

func (a *App) initCmd(args []string) int {
	fs := a.flags("init")
	archetype := fs.String("archetype", "", "app type: "+strings.Join(golden.Archetypes, ", "))
	cloud := fs.String("cloud", "", "aws, azure or gcp")
	name := fs.String("name", "", "app name")
	owner := fs.String("owner", "", "owning team")
	out := fs.String("out", "golden-path.yaml", "file to write")
	force := fs.Bool("force", false, "overwrite an existing file")
	rest, err := parse(fs, args)
	if err != nil {
		return a.usageErr(err)
	}
	if len(rest) > 0 {
		return a.fail(exitUsage, "init takes flags only (got %q)", rest[0])
	}
	var missing []string
	for _, f := range []struct{ flag, v string }{{"--archetype", *archetype}, {"--cloud", *cloud}, {"--name", *name}, {"--owner", *owner}} {
		if f.v == "" {
			missing = append(missing, f.flag)
		}
	}
	if len(missing) > 0 {
		return a.fail(exitUsage, "missing %s", strings.Join(missing, ", "))
	}
	p, err := a.platform()
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	data, err := p.Init(golden.InitOptions{Archetype: *archetype, Cloud: *cloud, Name: *name, Owner: *owner, Now: a.Now()})
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	if res := p.Validate(*out, data, true, a.Now()); !res.Valid {
		a.printResult(res)
		return a.fail(exitFindings, "the generated contract doesn't validate; this is a bug in the %s example", *archetype)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(*out, flags, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return a.fail(exitUsage, "%s already exists; use --force to overwrite it", *out)
		}
		return a.fail(exitUsage, "%v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return a.fail(exitUsage, "%v", err)
	}
	if err := f.Close(); err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	fmt.Fprintf(a.Out, "wrote %s (%s on %s); next: gold validate %s\n", *out, *archetype, *cloud, *out)
	return exitOK
}

func (a *App) catalog(args []string) int {
	if len(args) == 0 {
		return a.fail(exitUsage, "catalog needs list, show <archetype>, modules or schema")
	}
	sub, args := args[0], args[1:]
	fs := a.flags("catalog " + sub)
	format := fs.String("format", "text", "text or json")
	rest, err := parse(fs, args)
	if err != nil {
		return a.usageErr(err)
	}
	if !checkFormat(*format) {
		return a.fail(exitUsage, "--format must be text or json")
	}
	p, err := a.platform()
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	cat := p.Catalog

	switch sub {
	case "schema":
		a.Out.Write(p.SchemaRaw)
		if len(p.SchemaRaw) > 0 && p.SchemaRaw[len(p.SchemaRaw)-1] != '\n' {
			fmt.Fprintln(a.Out)
		}
	case "list":
		if *format == "json" {
			a.writeJSON(cat.Archetypes)
			break
		}
		tw := tabwriter.NewWriter(a.Out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ARCHETYPE\tRUNTIME (DEV)\tSUMMARY")
		for _, name := range golden.Archetypes {
			info := cat.Archetypes[name]
			fmt.Fprintf(tw, "%s\t%s (%s)\t%s\n", name, info.Runtime.Default, info.Runtime.Dev, info.Summary)
		}
		tw.Flush()
	case "show":
		if len(rest) != 1 {
			return a.fail(exitUsage, "catalog show takes one archetype")
		}
		info, ok := cat.Archetypes[rest[0]]
		if !ok {
			return a.fail(exitUsage, "unknown archetype %q (use one of %s)", rest[0], strings.Join(golden.Archetypes, ", "))
		}
		if *format == "json" {
			a.writeJSON(map[string]any{"archetype": rest[0], "info": info, "modules": modulesOf(cat, info.Modules)})
			break
		}
		fmt.Fprintf(a.Out, "%s: %s\nruntime: %s (dev: %s)\n", rest[0], info.Summary, info.Runtime.Default, info.Runtime.Dev)
		if len(info.Addons) > 0 {
			fmt.Fprintf(a.Out, "add-ons: %s\n", strings.Join(info.Addons, ", "))
		}
		if info.Composed {
			fmt.Fprintf(a.Out, "modules: any catalog module, within the custom-path guardrails (see: gold catalog modules)\n")
			break
		}
		fmt.Fprintln(a.Out)
		writeModules(a.Out, cat, info.Modules)
	case "modules":
		names := make([]string, 0, len(cat.Modules))
		for n := range cat.Modules {
			names = append(names, n)
		}
		sort.Strings(names)
		if *format == "json" {
			a.writeJSON(cat.Modules)
			break
		}
		writeModules(a.Out, cat, names)
	default:
		return a.fail(exitUsage, "unknown catalog command %q", sub)
	}
	return exitOK
}

func modulesOf(cat golden.Catalog, names []string) map[string]golden.Module {
	out := map[string]golden.Module{}
	for _, n := range names {
		out[n] = cat.Modules[n]
	}
	return out
}

func writeModules(w io.Writer, cat golden.Catalog, names []string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MODULE\tPUBLIC\tAWS\tAZURE\tGCP")
	for _, n := range names {
		m := cat.Modules[n]
		pub := "no"
		if m.Public {
			pub = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", n, pub, m.Services["aws"], m.Services["azure"], m.Services["gcp"])
	}
	tw.Flush()
}

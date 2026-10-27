package app

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/embedded"
	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/skill"
)

func (a *App) home() string {
	if h := a.Getenv("HOME"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

func (a *App) skillRoot(scope, dir string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return skill.Root(scope, dir, a.home(), cwd)
}

func (a *App) skillCmd(args []string) int {
	if len(args) == 0 {
		return a.fail(exitUsage, "skill needs install or print")
	}
	sub, args := args[0], args[1:]
	fs := a.flags("skill " + sub)
	scope := fs.String("scope", "user", "install: user or project")
	dir := fs.String("dir", "", "install: the folder that holds skills (overrides --scope)")
	force := fs.Bool("force", false, "install: replace a folder gold didn't create")
	rest, err := parse(fs, args)
	if err != nil {
		return a.usageErr(err)
	}
	if len(rest) > 0 {
		return a.fail(exitUsage, "skill %s takes flags only (got %q)", sub, rest[0])
	}
	switch sub {
	case "print":
		if err := skill.Print(a.Out); err != nil {
			return a.fail(exitUsage, "%v", err)
		}
	case "install":
		root, err := a.skillRoot(*scope, *dir)
		if err != nil {
			return a.fail(exitUsage, "%v", err)
		}
		dest, err := skill.Install(root, a.Version, embedded.FS(), *force)
		if err != nil {
			return a.fail(exitUsage, "%v", err)
		}
		fmt.Fprintf(a.Out, "installed the golden-path skill %s in %s\n", a.Version, dest)
	default:
		return a.fail(exitUsage, "unknown skill command %q (use install or print)", sub)
	}
	return exitOK
}

type check struct {
	Name    string `json:"name"`
	Level   string `json:"level"` // ok, warn or fail
	Message string `json:"message"`
}

func (a *App) doctor(args []string) int {
	fs := a.flags("doctor")
	strict := fs.Bool("strict", false, "treat warnings as failures")
	format := fs.String("format", "text", "text or json")
	rest, err := parse(fs, args)
	if err != nil {
		return a.usageErr(err)
	}
	if len(rest) > 0 || !checkFormat(*format) {
		return a.fail(exitUsage, "doctor takes --strict and --format text|json")
	}

	var checks []check
	add := func(name, level, format string, args ...any) {
		checks = append(checks, check{name, level, fmt.Sprintf(format, args...)})
	}
	add("gold", "ok", "%s on %s/%s", a.Version, runtime.GOOS, runtime.GOARCH)

	p, perr := a.platform()
	switch {
	case perr != nil:
		add("platform data", "fail", "%v", strings.ReplaceAll(perr.Error(), "\n", "; "))
	default:
		src := "built into this binary"
		if dir := a.Getenv("GOLD_GOLDEN_PATHS_DIR"); dir != "" {
			src = "read from " + dir
			add("platform data override", "warn", "GOLD_GOLDEN_PATHS_DIR is set; results may differ from the released tool")
		}
		add("platform data", "ok", "%d app types, %d modules, %s", len(p.Catalog.Archetypes), len(p.Catalog.Modules), src)
	}

	if p != nil {
		data, err := os.ReadFile("golden-path.yaml")
		switch {
		case os.IsNotExist(err):
			add("contract", "ok", "no golden-path.yaml in this folder")
		case err != nil:
			add("contract", "fail", "%v", err)
		default:
			res := p.Validate("golden-path.yaml", data, false, a.Now())
			errs, warns := 0, 0
			for _, f := range res.Findings {
				if f.Severity == "warning" {
					warns++
				} else {
					errs++
				}
			}
			switch {
			case errs > 0:
				add("contract", "fail", "golden-path.yaml has %d error(s); run: gold validate", errs)
			case warns > 0:
				add("contract", "warn", "golden-path.yaml is valid with %d warning(s); run: gold validate", warns)
			default:
				add("contract", "ok", "golden-path.yaml is valid")
			}
		}
	}

	installed := 0
	for _, scope := range []string{"user", "project"} {
		root, err := a.skillRoot(scope, "")
		if err != nil {
			continue
		}
		st := skill.Check(root, a.Version)
		name := "skill (" + scope + ")"
		switch st.State {
		case skill.NotInstalled:
			continue
		case skill.Current:
			add(name, "ok", "%s at %s", st.State, st.Path)
		case skill.Older:
			add(name, "warn", "version %s is %s; run: gold skill install --scope %s", st.Installed, st.State, scope)
		case skill.Newer:
			add(name, "warn", "version %s is %s; update gold", st.Installed, st.State)
		default:
			add(name, "warn", "%s is %s; leaving it alone", st.Path, st.State)
		}
		installed++
	}
	if installed == 0 {
		add("skill", "warn", "not installed; run: gold skill install")
	}

	status := exitOK
	for _, c := range checks {
		if c.Level == "fail" || (*strict && c.Level == "warn") {
			status = exitFindings
		}
	}
	if *format == "json" {
		a.writeJSON(map[string]any{"ok": status == exitOK, "checks": checks})
		return status
	}
	for _, c := range checks {
		fmt.Fprintf(a.Out, "%-5s %s: %s\n", c.Level, c.Name, c.Message)
	}
	return status
}

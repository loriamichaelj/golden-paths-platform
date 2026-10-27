// Package skill carries the agent skill inside the gold binary, so the tool and
// the instructions that describe it are always the same version.
package skill

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

//go:embed files
var content embed.FS

// Name is the skill's folder name.
const Name = "golden-path"

// MarkerFile records which gold version wrote the skill folder. Its presence
// also tells us the folder is ours to replace.
const MarkerFile = ".gold-skill-version"

// Root returns the folder that holds skills for a scope: "user" is the
// current user's skills folder, "project" is the one in the working directory,
// and an explicit dir overrides both.
func Root(scope, dir, home, cwd string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	switch scope {
	case "", "user":
		if home == "" {
			return "", errors.New("cannot find the home folder; pass --dir")
		}
		return filepath.Join(home, ".claude", "skills"), nil
	case "project":
		return filepath.Join(cwd, ".claude", "skills"), nil
	}
	return "", fmt.Errorf("unknown scope %q (use user or project)", scope)
}

// Print writes SKILL.md, the entry point of the skill.
func Print(w io.Writer) error {
	b, err := content.ReadFile("files/" + Name + "/SKILL.md")
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// Files lists every file in the embedded skill, relative to the skill folder.
func Files() ([]string, error) {
	var out []string
	err := fs.WalkDir(content, "files/"+Name, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		out = append(out, strings.TrimPrefix(p, "files/"+Name+"/"))
		return nil
	})
	return out, err
}

// Read returns one embedded file by its path inside the skill folder.
func Read(name string) ([]byte, error) { return content.ReadFile(path.Join("files", Name, name)) }

// Install writes the skill to root/golden-path, together with the example
// contracts from examples (a folder of *.yaml files), and returns the folder.
// An existing folder is replaced only when gold wrote it or force is set.
func Install(root, version string, examples fs.FS, force bool) (string, error) {
	dest := filepath.Join(root, Name)
	if info, err := os.Stat(dest); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("%s exists and is not a folder", dest)
		}
		if _, err := os.Stat(filepath.Join(dest, MarkerFile)); err != nil && !force {
			return "", fmt.Errorf("%s exists and was not installed by gold; use --force to replace it", dest)
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp(root, ".golden-path-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	names, err := Files()
	if err != nil {
		return "", err
	}
	for _, name := range names {
		b, err := Read(name)
		if err != nil {
			return "", err
		}
		if err := write(filepath.Join(tmp, filepath.FromSlash(name)), b); err != nil {
			return "", err
		}
	}
	entries, err := fs.ReadDir(examples, "examples")
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := fs.ReadFile(examples, path.Join("examples", e.Name()))
		if err != nil {
			return "", err
		}
		if err := write(filepath.Join(tmp, "examples", e.Name()), b); err != nil {
			return "", err
		}
	}
	if err := write(filepath.Join(tmp, MarkerFile), []byte(version+"\n")); err != nil {
		return "", err
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", err
	}
	if err := os.Chmod(dest, 0o755); err != nil { // MkdirTemp makes the folder private
		return "", err
	}
	return dest, nil
}

func write(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

// State says how an installed skill compares with the running gold.
type State string

const (
	NotInstalled State = "not installed"
	Current      State = "current"
	Older        State = "older than this gold"
	Newer        State = "newer than this gold"
	Unmanaged    State = "not installed by gold"
)

// Status is what Check finds.
type Status struct {
	Path      string
	Installed string
	State     State
}

// Check compares the skill under root with the running gold version. A
// development build ("dev" or any non-numeric version) treats an installed
// skill as current, because there is nothing to compare.
func Check(root, version string) Status {
	dest := filepath.Join(root, Name)
	st := Status{Path: dest}
	info, err := os.Stat(dest)
	if err != nil || !info.IsDir() {
		st.State = NotInstalled
		return st
	}
	b, err := os.ReadFile(filepath.Join(dest, MarkerFile))
	if err != nil {
		st.State = Unmanaged
		return st
	}
	st.Installed = strings.TrimSpace(string(b))
	have, ok1 := parse(st.Installed)
	want, ok2 := parse(version)
	switch {
	case !ok1 || !ok2 || have == want:
		st.State = Current
	case less(have, want):
		st.State = Older
	default:
		st.State = Newer
	}
	return st
}

type ver [3]int

func parse(s string) (ver, bool) {
	core, _, _ := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return ver{}, false
	}
	var v ver
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return ver{}, false
		}
		v[i] = n
	}
	return v, true
}

func less(a, b ver) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

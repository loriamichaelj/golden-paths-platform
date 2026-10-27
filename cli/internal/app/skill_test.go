package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// goldIn runs gold with a fake HOME, from dir, at a chosen version.
func goldIn(t *testing.T, dir, home, version string, args ...string) run {
	t.Helper()
	if home == "" {
		t.Fatal("tests must give gold a temporary HOME; an empty one falls back to the real home folder")
	}
	wd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	var out, errb bytes.Buffer
	a := &App{Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Version: version,
		Getenv: func(k string) string {
			if k == "HOME" {
				return home
			}
			return ""
		}}
	return run{a.Run(args), out.String(), errb.String()}
}

func TestSkillInstallScopes(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()

	r := goldIn(t, work, home, "1.0.0", "skill", "install")
	if r.code != 0 || !strings.Contains(r.out, filepath.Join(home, ".claude", "skills", "golden-path")) {
		t.Fatalf("user scope: %+v", r)
	}
	for _, f := range []string{"SKILL.md", "reference/contract.md", "reference/decision-guide.md", "reference/custom-paths.md", "examples/single-api.yaml", "examples/custom.yaml", ".gold-skill-version"} {
		if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "golden-path", f)); err != nil {
			t.Errorf("user install lacks %s", f)
		}
	}

	r = goldIn(t, work, home, "1.0.0", "skill", "install", "--scope", "project")
	if r.code != 0 {
		t.Fatalf("project scope: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(work, ".claude", "skills", "golden-path", "SKILL.md")); err != nil {
		t.Error("project install should land under the working folder")
	}

	custom := t.TempDir()
	r = goldIn(t, work, home, "1.0.0", "skill", "install", "--dir", custom)
	if r.code != 0 {
		t.Fatalf("--dir: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(custom, "golden-path", "SKILL.md")); err != nil {
		t.Error("--dir install should land in the chosen folder")
	}
}

func TestSkillInstallProtectsOtherFoldersAndRejectsBadInput(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()
	mine := filepath.Join(home, ".claude", "skills", "golden-path")
	os.MkdirAll(mine, 0o755)
	os.WriteFile(filepath.Join(mine, "notes.txt"), []byte("mine"), 0o644)
	if r := goldIn(t, work, home, "1.0.0", "skill", "install"); r.code != 2 || !strings.Contains(r.err, "--force") {
		t.Errorf("refuse: %+v", r)
	}
	if r := goldIn(t, work, home, "1.0.0", "skill", "install", "--force"); r.code != 0 {
		t.Errorf("force: %+v", r)
	}
	for name, args := range map[string][]string{
		"no subcommand": {"skill"},
		"unknown":       {"skill", "remove"},
		"bad scope":     {"skill", "install", "--scope", "galaxy"},
		"stray args":    {"skill", "install", "stray"},
	} {
		if r := goldIn(t, work, home, "1.0.0", args...); r.code != 2 {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestSkillPrint(t *testing.T) {
	r := goldIn(t, t.TempDir(), t.TempDir(), "1.0.0", "skill", "print")
	if r.code != 0 || !strings.Contains(r.out, "name: golden-path") || !strings.Contains(r.out, "gold validate --strict") {
		t.Errorf("%+v", r)
	}
}

func TestDoctor(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()

	// Nothing set up: fine, with a nudge to install the skill.
	r := goldIn(t, work, home, "1.0.0", "doctor")
	if r.code != 0 || !strings.Contains(r.out, "ok    platform data: 7 app types") || !strings.Contains(r.out, "warn  skill: not installed") {
		t.Fatalf("fresh: %+v", r)
	}
	if r := goldIn(t, work, home, "1.0.0", "doctor", "--strict"); r.code != 1 {
		t.Errorf("strict should fail on the skill warning: %+v", r)
	}

	// Current skill, valid contract.
	goldIn(t, work, home, "1.0.0", "skill", "install")
	os.WriteFile(filepath.Join(work, "golden-path.yaml"), []byte(good), 0o644)
	r = goldIn(t, work, home, "1.0.0", "doctor", "--strict")
	if r.code != 0 || !strings.Contains(r.out, "ok    contract: golden-path.yaml is valid") || !strings.Contains(r.out, "ok    skill (user): current") {
		t.Errorf("healthy: %+v", r)
	}

	// An older skill is flagged, and the fix is named.
	r = goldIn(t, work, home, "1.1.0", "doctor")
	if r.code != 0 || !strings.Contains(r.out, "warn  skill (user): version 1.0.0 is older than this gold; run: gold skill install --scope user") {
		t.Errorf("older: %+v", r)
	}
	if r := goldIn(t, work, home, "1.1.0", "doctor", "--strict"); r.code != 1 {
		t.Errorf("older skill under --strict: %+v", r)
	}
	r = goldIn(t, work, home, "0.9.0", "doctor")
	if !strings.Contains(r.out, "is newer than this gold; update gold") {
		t.Errorf("newer: %+v", r)
	}

	// A broken contract fails the check.
	os.WriteFile(filepath.Join(work, "golden-path.yaml"), []byte(strings.Replace(good, "tier: silver", "tier: platinum", 1)), 0o644)
	r = goldIn(t, work, home, "1.0.0", "doctor")
	if r.code != 1 || !strings.Contains(r.out, "fail  contract: golden-path.yaml has 1 error(s)") {
		t.Errorf("broken contract: %+v", r)
	}

	// A contract with only warnings is a warning.
	warn := strings.NewReplacer("data_class: internal", "data_class: confidential", "network: private", "network: public").Replace(good)
	os.WriteFile(filepath.Join(work, "golden-path.yaml"), []byte(warn), 0o644)
	if r := goldIn(t, work, home, "1.0.0", "doctor"); r.code != 0 || !strings.Contains(r.out, "warn  contract: golden-path.yaml is valid with 1 warning(s)") {
		t.Errorf("warning contract: %+v", r)
	}
}

func TestDoctorUnmanagedSkillAndJSON(t *testing.T) {
	home, work := t.TempDir(), t.TempDir()
	mine := filepath.Join(home, ".claude", "skills", "golden-path")
	os.MkdirAll(mine, 0o755)
	r := goldIn(t, work, home, "1.0.0", "doctor", "--format", "json")
	var got struct {
		OK     bool    `json:"ok"`
		Checks []check `json:"checks"`
	}
	if err := json.Unmarshal([]byte(r.out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.out)
	}
	if !got.OK || len(got.Checks) < 4 {
		t.Errorf("unexpected: %+v", got)
	}
	found := false
	for _, c := range got.Checks {
		if c.Name == "skill (user)" && c.Level == "warn" && strings.Contains(c.Message, "not installed by gold") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unmanaged skill folder should be reported and left alone: %+v", got.Checks)
	}
	if r := goldIn(t, work, home, "1.0.0", "doctor", "extra"); r.code != 2 {
		t.Errorf("stray argument: %+v", r)
	}
}

func TestDoctorFlagsASourceOverride(t *testing.T) {
	env := map[string]string{"GOLD_GOLDEN_PATHS_DIR": filepath.Join("..", "..", "..", "golden-paths")}
	if r := gold(t, env, "doctor"); !strings.Contains(r.out, "warn  platform data override") {
		t.Errorf("%+v", r)
	}
	broken := t.TempDir()
	if r := gold(t, map[string]string{"GOLD_GOLDEN_PATHS_DIR": broken}, "doctor"); r.code != 1 || !strings.Contains(r.out, "fail  platform data") {
		t.Errorf("broken data should fail doctor: %+v", r)
	}
}

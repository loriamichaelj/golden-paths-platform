package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/golden"
)

var fixedNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

type run struct {
	code     int
	out, err string
}

func gold(t *testing.T, env map[string]string, args ...string) run {
	t.Helper()
	var out, errb bytes.Buffer
	a := &App{Out: &out, Err: &errb, Now: func() time.Time { return fixedNow }, Version: "test",
		Getenv: func(k string) string { return env[k] }}
	return run{a.Run(args), out.String(), errb.String()}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const good = `apiVersion: platform.example.com/v1
kind: GoldenPath
metadata:
  name: hello-api
  owner: team-a
spec:
  archetype: single-api
  cloud: aws
  tier: silver
  size: S
  cost_profile: balanced
  arch: arm64
  data_class: internal
  network: private
  environments: [dev, prod]
  lifecycle: persistent
`

func TestNoArgsAndUnknownCommand(t *testing.T) {
	if r := gold(t, nil); r.code != 2 || !strings.Contains(r.err, "Usage:") {
		t.Errorf("no args: %+v", r)
	}
	if r := gold(t, nil, "frobnicate"); r.code != 2 || !strings.Contains(r.err, `unknown command "frobnicate"`) {
		t.Errorf("unknown command: %+v", r)
	}
	if r := gold(t, nil, "help"); r.code != 0 || !strings.Contains(r.out, "gold validate") {
		t.Errorf("help: %+v", r)
	}
	if r := gold(t, nil, "version"); r.code != 0 || r.out != "gold test\n" {
		t.Errorf("version: %+v", r)
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	ok := writeFile(t, dir, "golden-path.yaml", good)
	bad := writeFile(t, dir, "bad.yaml", strings.Replace(good, "tier: silver", "tier: platinum", 1))

	if r := gold(t, nil, "validate", ok); r.code != 0 || !strings.HasPrefix(r.out, "ok  ") {
		t.Errorf("valid file: %+v", r)
	}
	// A folder resolves to the golden-path.yaml inside it.
	if r := gold(t, nil, "validate", dir); r.code != 0 {
		t.Errorf("folder: %+v", r)
	}
	r := gold(t, nil, "validate", bad)
	if r.code != 1 || !strings.Contains(r.out, "bad.yaml:9: error: spec.tier: must be one of bronze, silver, gold") {
		t.Errorf("bad file: %+v", r)
	}
	// Flags may follow the path.
	if r := gold(t, nil, "validate", ok, "--strict"); r.code != 0 {
		t.Errorf("flag after path: %+v", r)
	}
	if r := gold(t, nil, "validate", filepath.Join(dir, "missing.yaml")); r.code != 2 || !strings.Contains(r.err, "no such file") {
		t.Errorf("missing file: %+v", r)
	}
	// Several files: the worst status wins and every file is reported.
	r = gold(t, nil, "validate", ok, bad)
	if r.code != 1 || !strings.Contains(r.out, "ok  ") || !strings.Contains(r.out, "error") {
		t.Errorf("two files: %+v", r)
	}
}

func TestValidateDefaultsToLocalContract(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "golden-path.yaml", good)
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if r := gold(t, nil, "validate"); r.code != 0 {
		t.Errorf("default path: %+v", r)
	}
}

func TestValidateJSON(t *testing.T) {
	dir := t.TempDir()
	bad := writeFile(t, dir, "bad.yaml", strings.Replace(good, "tier: silver", "tier: platinum", 1))
	r := gold(t, nil, "validate", "--format", "json", bad)
	if r.code != 1 {
		t.Fatalf("code %d", r.code)
	}
	var got struct {
		Valid bool `json:"valid"`
		Files []struct {
			Path     string           `json:"path"`
			Valid    bool             `json:"valid"`
			Findings []golden.Finding `json:"findings"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(r.out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, r.out)
	}
	if got.Valid || len(got.Files) != 1 || got.Files[0].Valid || len(got.Files[0].Findings) != 1 || got.Files[0].Findings[0].Path != "spec.tier" {
		t.Errorf("unexpected JSON: %+v", got)
	}
	if r := gold(t, nil, "validate", "--format", "xml", bad); r.code != 2 {
		t.Errorf("bad format: %+v", r)
	}
}

func TestStrictTurnsWarningsIntoFailures(t *testing.T) {
	dir := t.TempDir()
	warn := writeFile(t, dir, "warn.yaml", strings.NewReplacer("data_class: internal", "data_class: confidential", "network: private", "network: public").Replace(good))
	if r := gold(t, nil, "validate", warn); r.code != 0 || !strings.Contains(r.out, "warning") || !strings.Contains(r.out, "1 warning(s)") {
		t.Errorf("non-strict: %+v", r)
	}
	if r := gold(t, nil, "validate", "--strict", warn); r.code != 1 {
		t.Errorf("strict: %+v", r)
	}
}

func TestExplain(t *testing.T) {
	dir := t.TempDir()
	ok := writeFile(t, dir, "golden-path.yaml", good)
	r := gold(t, nil, "explain", ok)
	if r.code != 0 || !strings.Contains(r.out, "Resources on aws") || !strings.Contains(r.out, "ECS on Fargate") {
		t.Errorf("text: %+v", r)
	}
	r = gold(t, nil, "explain", "--format", "json", ok)
	var ex golden.Explanation
	if r.code != 0 || json.Unmarshal([]byte(r.out), &ex) != nil || ex.App != "hello-api" || ex.Cloud != "aws" {
		t.Errorf("json: %+v", r)
	}
	bad := writeFile(t, dir, "bad.yaml", strings.Replace(good, "tier: silver", "tier: platinum", 1))
	if r := gold(t, nil, "explain", bad); r.code != 1 || !strings.Contains(r.err, "fix these errors") {
		t.Errorf("invalid contract: %+v", r)
	}
	if r := gold(t, nil, "explain", ok, ok); r.code != 2 {
		t.Errorf("two contracts: %+v", r)
	}
}

func TestInit(t *testing.T) {
	for _, a := range golden.Archetypes {
		dir := t.TempDir()
		out := filepath.Join(dir, "golden-path.yaml")
		r := gold(t, nil, "init", "--archetype", a, "--cloud", "azure", "--name", "demo-app", "--owner", "team-z", "--out", out)
		if r.code != 0 || !strings.Contains(r.out, "wrote") {
			t.Fatalf("%s: %+v", a, r)
		}
		if v := gold(t, nil, "validate", "--strict", out); v.code != 0 {
			t.Fatalf("%s doesn't validate: %+v", a, v)
		}
	}
}

func TestInitRefusesToOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := writeFile(t, dir, "golden-path.yaml", "keep me\n")
	args := []string{"init", "--archetype", "single-api", "--cloud", "aws", "--name", "demo-app", "--owner", "team-z", "--out", out}
	if r := gold(t, nil, args...); r.code != 2 || !strings.Contains(r.err, "already exists") {
		t.Errorf("no force: %+v", r)
	}
	if b, _ := os.ReadFile(out); string(b) != "keep me\n" {
		t.Error("the existing file was changed")
	}
	if r := gold(t, nil, append(args, "--force")...); r.code != 0 {
		t.Errorf("force: %+v", r)
	}
}

func TestInitUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"missing flags": {"init", "--archetype", "single-api"},
		"bad cloud":     {"init", "--archetype", "single-api", "--cloud", "mars", "--name", "demo-app", "--owner", "team-z"},
		"bad name":      {"init", "--archetype", "single-api", "--cloud", "aws", "--name", "Demo", "--owner", "team-z"},
		"extra args":    {"init", "stray", "--archetype", "single-api", "--cloud", "aws", "--name", "demo-app", "--owner", "team-z"},
	} {
		if r := gold(t, nil, args...); r.code != 2 {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestCatalog(t *testing.T) {
	r := gold(t, nil, "catalog", "list")
	if r.code != 0 {
		t.Fatalf("list: %+v", r)
	}
	for _, a := range golden.Archetypes {
		if !strings.Contains(r.out, a) {
			t.Errorf("list lacks %s", a)
		}
	}
	if r := gold(t, nil, "catalog", "show", "microservices"); r.code != 0 || !strings.Contains(r.out, "EKS") || !strings.Contains(r.out, "istio") {
		t.Errorf("show: %+v", r)
	}
	if r := gold(t, nil, "catalog", "show", "custom"); r.code != 0 || !strings.Contains(r.out, "any catalog module") {
		t.Errorf("show custom: %+v", r)
	}
	if r := gold(t, nil, "catalog", "show", "nope"); r.code != 2 {
		t.Errorf("show unknown: %+v", r)
	}
	if r := gold(t, nil, "catalog", "show"); r.code != 2 {
		t.Errorf("show without name: %+v", r)
	}
	if r := gold(t, nil, "catalog", "modules"); r.code != 0 || !strings.Contains(r.out, "database-relational") || !strings.Contains(r.out, "Cloud Run") {
		t.Errorf("modules: %+v", r)
	}
	if r := gold(t, nil, "catalog", "nope"); r.code != 2 {
		t.Errorf("unknown subcommand: %+v", r)
	}
	if r := gold(t, nil, "catalog"); r.code != 2 {
		t.Errorf("no subcommand: %+v", r)
	}
	for _, args := range [][]string{{"catalog", "list", "--format", "json"}, {"catalog", "modules", "--format", "json"}, {"catalog", "show", "three-tier", "--format", "json"}, {"catalog", "schema"}} {
		r := gold(t, nil, args...)
		var v any
		if r.code != 0 || json.Unmarshal([]byte(r.out), &v) != nil {
			t.Errorf("%v isn't JSON: %+v", args, r)
		}
	}
}

// The embedded copy and golden-paths/ must agree; make check-sync enforces it
// byte for byte, and this proves the CLI behaves the same on either.
func TestSourceDirectoryOverride(t *testing.T) {
	env := map[string]string{"GOLD_GOLDEN_PATHS_DIR": filepath.Join("..", "..", "..", "golden-paths")}
	dir := t.TempDir()
	ok := writeFile(t, dir, "golden-path.yaml", good)
	if r := gold(t, env, "validate", "--strict", ok); r.code != 0 {
		t.Errorf("source dir: %+v", r)
	}
	if r := gold(t, map[string]string{"GOLD_GOLDEN_PATHS_DIR": dir}, "catalog", "list"); r.code != 2 {
		t.Errorf("a folder without platform data should fail: %+v", r)
	}
}

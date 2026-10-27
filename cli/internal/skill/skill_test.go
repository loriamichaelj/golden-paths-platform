package skill

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/embedded"
	"gitlab.com/michaeljloria/golden-paths-platform/cli/internal/golden"
)

func TestRoot(t *testing.T) {
	for _, c := range []struct {
		scope, dir, home, cwd, want string
		fail                        bool
	}{
		{"", "", "/h", "/w", "/h/.claude/skills", false},
		{"user", "", "/h", "/w", "/h/.claude/skills", false},
		{"project", "", "/h", "/w", "/w/.claude/skills", false},
		{"user", "/custom", "/h", "/w", "/custom", false},
		{"project", "/custom", "/h", "/w", "/custom", false},
		{"user", "", "", "/w", "", true},
		{"galaxy", "", "/h", "/w", "", true},
	} {
		got, err := Root(c.scope, c.dir, c.home, c.cwd)
		if (err != nil) != c.fail || got != c.want {
			t.Errorf("Root(%q,%q,%q,%q) = %q, %v", c.scope, c.dir, c.home, c.cwd, got, err)
		}
	}
}

func TestInstallWritesTheWholeSkill(t *testing.T) {
	root := t.TempDir()
	dest, err := Install(root, "1.2.3", embedded.FS(), false)
	if err != nil {
		t.Fatal(err)
	}
	if dest != filepath.Join(root, "golden-path") {
		t.Fatalf("dest %s", dest)
	}
	names, _ := Files()
	for _, n := range names {
		want, _ := Read(n)
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(n)))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s was not written intact: %v", n, err)
		}
	}
	for _, a := range golden.Archetypes {
		want, _ := os.ReadFile(filepath.Join("..", "..", "..", "golden-paths", "examples", a+".yaml"))
		got, err := os.ReadFile(filepath.Join(dest, "examples", a+".yaml"))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("example %s missing or different from golden-paths/: %v", a, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dest, MarkerFile)); strings.TrimSpace(string(b)) != "1.2.3" {
		t.Errorf("marker %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(root, ".golden-path-*")); len(left) != 0 {
		t.Errorf("temporary folders left behind: %v", left)
	}
	info, _ := os.Stat(dest)
	if info.Mode().Perm() != 0o755 {
		t.Errorf("folder mode %v", info.Mode().Perm())
	}
}

func TestInstallReplacesItsOwnFolderAndOnlyThat(t *testing.T) {
	root := t.TempDir()
	if _, err := Install(root, "1.0.0", embedded.FS(), false); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(root, "golden-path", "stale.txt")
	os.WriteFile(stale, []byte("x"), 0o644)
	if _, err := Install(root, "1.1.0", embedded.FS(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("a re-install should replace the folder, leaving no stale files")
	}
	if got := Check(root, "1.1.0"); got.State != Current || got.Installed != "1.1.0" {
		t.Errorf("after upgrade: %+v", got)
	}

	// A folder gold did not write is protected unless forced.
	other := t.TempDir()
	mine := filepath.Join(other, "golden-path")
	os.MkdirAll(mine, 0o755)
	os.WriteFile(filepath.Join(mine, "notes.txt"), []byte("mine"), 0o644)
	if _, err := Install(other, "1.0.0", embedded.FS(), false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want a refusal, got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(mine, "notes.txt")); string(b) != "mine" {
		t.Error("the refused install must not touch the folder")
	}
	if _, err := Install(other, "1.0.0", embedded.FS(), true); err != nil {
		t.Fatalf("force: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mine, "notes.txt")); !os.IsNotExist(err) {
		t.Error("force should replace the folder")
	}
	// A plain file in the way is never replaced.
	file := t.TempDir()
	os.WriteFile(filepath.Join(file, "golden-path"), []byte("a file"), 0o644)
	if _, err := Install(file, "1.0.0", embedded.FS(), true); err == nil {
		t.Error("a file named golden-path should block the install")
	}
}

func TestCheck(t *testing.T) {
	root := t.TempDir()
	if got := Check(root, "1.0.0"); got.State != NotInstalled {
		t.Errorf("empty: %+v", got)
	}
	if _, err := Install(root, "1.2.0", embedded.FS(), false); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		gold string
		want State
	}{
		{"1.2.0", Current}, {"1.2.5", Older}, {"1.10.0", Older}, {"2.0.0", Older},
		{"1.1.9", Newer}, {"0.9.0", Newer}, {"1.2.0-rc1", Current},
		{"dev", Current}, {"", Current},
	} {
		if got := Check(root, c.gold); got.State != c.want {
			t.Errorf("skill 1.2.0 vs gold %q: got %q, want %q", c.gold, got.State, c.want)
		}
	}
	os.Remove(filepath.Join(root, "golden-path", MarkerFile))
	if got := Check(root, "1.2.0"); got.State != Unmanaged {
		t.Errorf("no marker: %+v", got)
	}
}

func TestPrintIsTheEntryPoint(t *testing.T) {
	var b bytes.Buffer
	if err := Print(&b); err != nil || !strings.HasPrefix(b.String(), "---\nname: golden-path\n") {
		t.Fatalf("%v %q", err, b.String()[:40])
	}
}

// The tests below keep the skill's text honest as the platform changes.

func TestSkillHasValidFrontMatter(t *testing.T) {
	b, _ := Read("SKILL.md")
	m := regexp.MustCompile(`(?s)\A---\nname: (.+)\ndescription: (.+)\n---\n`).FindSubmatch(b)
	if m == nil {
		t.Fatal("SKILL.md needs front matter with name and description")
	}
	if string(m[1]) != Name {
		t.Errorf("name %q must match the folder %q", m[1], Name)
	}
	if n := len(m[2]); n < 40 || n > 400 {
		t.Errorf("description is %d characters; keep it specific but short", n)
	}
}

func TestEveryLinkedFileExists(t *testing.T) {
	names, _ := Files()
	have := map[string]bool{"examples/": true}
	for _, n := range names {
		have[n] = true
	}
	b, _ := Read("SKILL.md")
	refs := regexp.MustCompile("`((?:reference|examples)/[A-Za-z0-9._/-]*)`").FindAllSubmatch(b, -1)
	if len(refs) == 0 {
		t.Fatal("SKILL.md should point at its reference files")
	}
	for _, r := range refs {
		if !have[string(r[1])] {
			t.Errorf("SKILL.md points at %s, which isn't in the skill", r[1])
		}
	}
}

func TestContractGuideCoversEverySchemaField(t *testing.T) {
	p, err := golden.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			Spec struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"spec"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(p.SchemaRaw, &schema); err != nil {
		t.Fatal(err)
	}
	guide, _ := Read("reference/contract.md")
	text := string(guide)
	for field, def := range schema.Defs.Spec.Properties {
		if !strings.Contains(text, "`"+field+"`") {
			t.Errorf("contract.md does not describe spec.%s", field)
		}
		for _, v := range def.Enum {
			if !strings.Contains(text, "`"+v+"`") {
				t.Errorf("contract.md does not list %s value %q", field, v)
			}
		}
	}
}

func TestDecisionGuideCoversEveryAppType(t *testing.T) {
	guide, _ := Read("reference/decision-guide.md")
	for _, a := range golden.Archetypes {
		if !strings.Contains(string(guide), "`"+a+"`") {
			t.Errorf("decision-guide.md does not mention %s", a)
		}
	}
}

func TestCustomGuideMatchesTheRules(t *testing.T) {
	p, err := golden.Load(embedded.FS())
	if err != nil {
		t.Fatal(err)
	}
	guide, _ := Read("reference/custom-paths.md")
	text := string(guide)
	for _, in := range p.Catalog.Custom.LockedInputs {
		if !strings.Contains(text, "`"+in+"`") {
			t.Errorf("custom-paths.md does not list the locked input %s", in)
		}
	}
	for _, n := range []int{p.Catalog.Custom.MaxReviewDays, p.Catalog.Custom.MaxComponents} {
		if !strings.Contains(text, " "+strconv.Itoa(n)+" ") {
			t.Errorf("custom-paths.md does not state the limit %d", n)
		}
	}
	var public []string
	for name, m := range p.Catalog.Modules {
		if m.Public {
			public = append(public, name)
		}
	}
	if len(public) != 3 { // load balancer, CDN, object storage: the guide says so in words
		t.Errorf("the guide names three kinds of public component, the catalog has %v", public)
	}
}

func TestSkillMakesNoPromisesAboutUnshippedCommands(t *testing.T) {
	names, _ := Files()
	shipped := regexp.MustCompile("gold (validate|explain|init|catalog|doctor|skill|version)")
	for _, n := range names {
		b, _ := Read(n)
		for _, m := range regexp.MustCompile("`gold ([a-z]+)").FindAllSubmatch(b, -1) {
			if !shipped.Match(append([]byte("gold "), m[1]...)) {
				t.Errorf("%s mentions `gold %s`, which isn't a shipped command", n, m[1])
			}
		}
	}
}

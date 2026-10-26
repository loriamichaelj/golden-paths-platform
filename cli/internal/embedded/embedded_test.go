package embedded

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// source is golden-paths/ in the repository; the embedded copy must match it.
const source = "../../../golden-paths"

var parts = []string{"catalog.yaml", "schema", "defaults", "examples"}

// TestEmbeddedCopyMatchesSource fails when golden-paths/ changed but the copy
// built into the binary was not refreshed. CI sets GOLD_REQUIRE_SYNC so a
// missing source folder is an error there; elsewhere the test is skipped.
func TestEmbeddedCopyMatchesSource(t *testing.T) {
	if _, err := os.Stat(source); err != nil {
		if os.Getenv("GOLD_REQUIRE_SYNC") != "" {
			t.Fatalf("golden-paths/ not found next to the CLI: %v", err)
		}
		t.Skip("golden-paths/ is not next to the CLI; nothing to compare")
	}
	src := os.DirFS(source)
	emb := FS()
	for _, part := range parts {
		want := readTree(t, src, part)
		got := readTree(t, emb, part)
		for name, data := range want {
			other, ok := got[name]
			switch {
			case !ok:
				t.Errorf("%s is missing from the embedded copy; run the sync", name)
			case !bytes.Equal(data, other):
				t.Errorf("%s differs from the embedded copy; run the sync", name)
			}
		}
		for name := range got {
			if _, ok := want[name]; !ok {
				t.Errorf("%s is embedded but no longer in golden-paths/; run the sync", name)
			}
		}
	}
}

func readTree(t *testing.T, fsys fs.FS, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		out[filepath.ToSlash(p)] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("no files under %s", root)
	}
	return out
}

package release

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// moduleDir is the cli module, which these tests build for real.
const moduleDir = "../.."

func host() Target { return Target{runtime.GOOS, runtime.GOARCH} }

func TestVersionFromTag(t *testing.T) {
	for _, c := range []struct {
		prefix, tag, want string
		ok                bool
	}{
		{"gold-v", "gold-v0.1.0", "0.1.0", true},
		{"gold-v", "gold-v12.34.56", "12.34.56", true},
		{"scanner-v", "scanner-v1.0.0", "1.0.0", true},
		{"gold-v", "gold-v1.0", "", false},
		{"gold-v", "gold-v1.0.0-rc1", "", false},
		{"gold-v", "scanner-v1.0.0", "", false},
		{"gold-v", "v1.0.0", "", false},
		{"gold-v", "", "", false},
	} {
		got, err := VersionFromTag(c.prefix, c.tag)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("VersionFromTag(%q, %q) = %q, %v", c.prefix, c.tag, got, err)
		}
	}
}

func TestParseTargets(t *testing.T) {
	got, err := ParseTargets("linux/amd64, darwin/arm64")
	if err != nil || len(got) != 2 || got[1] != (Target{"darwin", "arm64"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"linux", "linux/", "/amd64", ""} {
		if _, err := ParseTargets(bad); err == nil {
			t.Errorf("want an error for %q", bad)
		}
	}
	if n := len(DefaultTargets()); n != 6 {
		t.Errorf("want 6 default targets, got %d", n)
	}
}

func TestDuplicateTargetsBuildOnce(t *testing.T) {
	got := uniqueTargets([]Target{{"linux", "amd64"}, {"darwin", "arm64"}, {"linux", "amd64"}})
	if len(got) != 2 || got[0] != (Target{"linux", "amd64"}) || got[1] != (Target{"darwin", "arm64"}) {
		t.Fatalf("got %v", got)
	}
	out := build(t, "1.0.0", Target{"linux", "amd64"}, Target{"linux", "amd64"})
	entries, _ := os.ReadDir(out)
	if len(entries) != 2 { // one archive and checksums.txt
		t.Errorf("want 1 archive plus checksums, got %d files", len(entries))
	}
}

func TestArchiveName(t *testing.T) {
	if got := ArchiveName("gold", Target{"linux", "amd64"}); got != "gold_linux_amd64.tar.gz" {
		t.Error(got)
	}
	if got := ArchiveName("gold", Target{"windows", "arm64"}); got != "gold_windows_arm64.zip" {
		t.Error(got)
	}
}

func build(t *testing.T, version string, targets ...Target) string {
	t.Helper()
	out := t.TempDir()
	if _, err := Build(BuildOptions{ModuleDir: moduleDir, Version: version, Out: out, Targets: targets}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBuildProducesVerifiedArchives(t *testing.T) {
	// The host may already be one of these (a Linux amd64 runner is), so count distinct targets.
	targets := []Target{host(), {"linux", "amd64"}, {"windows", "amd64"}}
	out := build(t, "9.9.9", targets...)

	for _, name := range []string{ArchiveName("gold", host()), "gold_linux_amd64.tar.gz", "gold_windows_amd64.zip", ChecksumsFile} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("missing %s", name)
		}
	}
	if err := VerifyChecksums(out); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(out, ChecksumsFile))
	lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
	if want := len(uniqueTargets(targets)); len(lines) != want {
		t.Fatalf("want %d checksum lines, got %q", want, lines)
	}
	for _, l := range lines {
		if parts := strings.Split(l, "  "); len(parts) != 2 || len(parts[0]) != 64 {
			t.Errorf("not in sha256sum format: %q", l)
		}
	}

	// A tar.gz holds one executable with no owner and the epoch timestamp.
	f, err := os.Open(filepath.Join(out, "gold_linux_amd64.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Name != "gold" || hdr.Mode != 0o755 || hdr.Uid != 0 || hdr.Gid != 0 || !hdr.ModTime.Equal(epoch) {
		t.Errorf("unexpected header: %+v", hdr)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Error("the archive should hold exactly one file")
	}

	// The Windows archive is a zip holding gold.exe.
	zr, err := zip.OpenReader(filepath.Join(out, "gold_windows_amd64.zip"))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	if len(zr.File) != 1 || zr.File[0].Name != "gold.exe" {
		t.Errorf("unexpected zip contents: %v", zr.File)
	}
}

func TestBuiltBinaryReportsItsVersion(t *testing.T) {
	out := build(t, "9.9.9", host())
	f, err := os.Open(filepath.Join(out, ArchiveName("gold", host())))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	tr := tar.NewReader(gz)
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "gold")
	var data bytes.Buffer
	if _, err := io.Copy(&data, tr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, data.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := exec.Command(bin, "version").Output()
	if err != nil || strings.TrimSpace(string(got)) != "gold 9.9.9" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestBuildIsReproducible(t *testing.T) {
	a := build(t, "1.2.3", host(), Target{"linux", "arm64"})
	b := build(t, "1.2.3", host(), Target{"linux", "arm64"})
	sa, _ := os.ReadFile(filepath.Join(a, ChecksumsFile))
	sb, _ := os.ReadFile(filepath.Join(b, ChecksumsFile))
	if string(sa) != string(sb) {
		t.Fatalf("two builds differ:\n%s\n%s", sa, sb)
	}
}

func TestBuildRejectsBadVersion(t *testing.T) {
	for _, v := range []string{"", "1.2", "v1.2.3", "1.2.3 beta"} {
		if _, err := Build(BuildOptions{ModuleDir: moduleDir, Version: v, Out: t.TempDir(), Targets: []Target{host()}}); err == nil {
			t.Errorf("want an error for version %q", v)
		}
	}
	// A pre-release suffix is allowed for CI dry runs.
	if _, err := Build(BuildOptions{ModuleDir: moduleDir, Version: "0.0.0-ci", Out: t.TempDir(), Targets: []Target{host()}}); err != nil {
		t.Error(err)
	}
}

func TestBuildReportsCompileFailures(t *testing.T) {
	_, err := Build(BuildOptions{ModuleDir: moduleDir, Package: "./does-not-exist", Version: "1.0.0", Out: t.TempDir(), Targets: []Target{host()}})
	if err == nil || !strings.Contains(err.Error(), "build "+host().String()) {
		t.Fatalf("want a build error naming the target, got %v", err)
	}
}

func TestVerifyDetectsProblems(t *testing.T) {
	good := build(t, "1.0.0", host())
	copyDir := func() string {
		d := t.TempDir()
		entries, _ := os.ReadDir(good)
		for _, e := range entries {
			b, _ := os.ReadFile(filepath.Join(good, e.Name()))
			os.WriteFile(filepath.Join(d, e.Name()), b, 0o644)
		}
		return d
	}
	name := ArchiveName("gold", host())

	d := copyDir()
	f, _ := os.OpenFile(filepath.Join(d, name), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("tampered")
	f.Close()
	if err := VerifyChecksums(d); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("tampered archive: %v", err)
	}

	d = copyDir()
	os.Remove(filepath.Join(d, name))
	if err := VerifyChecksums(d); err == nil {
		t.Error("missing archive should fail")
	}

	d = copyDir()
	os.WriteFile(filepath.Join(d, "gold_extra_amd64.tar.gz"), []byte("x"), 0o644)
	if err := VerifyChecksums(d); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Errorf("unlisted archive: %v", err)
	}

	d = copyDir()
	os.WriteFile(filepath.Join(d, ChecksumsFile), []byte("not a checksum line\n"), 0o644)
	if err := VerifyChecksums(d); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("malformed line: %v", err)
	}

	if err := VerifyChecksums(t.TempDir()); err == nil {
		t.Error("an empty folder should fail")
	}
}

type recorded struct {
	method, path, token string
	body                []byte
}

func registry(t *testing.T, status int) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recorded{r.Method, r.URL.Path, r.Header.Get("JOB-TOKEN"), b})
		mu.Unlock()
		w.WriteHeader(status)
		io.WriteString(w, "response body")
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestUpload(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "gold_linux_amd64.tar.gz"), []byte("archive-bytes"), 0o644)
	os.WriteFile(filepath.Join(dir, ChecksumsFile), []byte("sums"), 0o644)
	os.Mkdir(filepath.Join(dir, "subdir"), 0o755)
	srv, got := registry(t, http.StatusCreated)

	u := Uploader{BaseURL: srv.URL + "/api/v4/", ProjectID: "42", Token: "job-token", Client: srv.Client()}
	sent, err := u.Upload("gold", "1.2.3", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || len(*got) != 2 {
		t.Fatalf("sent %v, server saw %d requests", sent, len(*got))
	}
	want := map[string]string{
		"/api/v4/projects/42/packages/generic/gold/1.2.3/checksums.txt":           "sums",
		"/api/v4/projects/42/packages/generic/gold/1.2.3/gold_linux_amd64.tar.gz": "archive-bytes",
	}
	for _, r := range *got {
		if r.method != http.MethodPut || r.token != "job-token" || string(r.body) != want[r.path] {
			t.Errorf("unexpected request: %+v", r)
		}
		delete(want, r.path)
	}
	if len(want) != 0 {
		t.Errorf("missing uploads: %v", want)
	}
}

func TestUploadFailures(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ChecksumsFile), []byte("sums"), 0o644)

	srv, _ := registry(t, http.StatusInternalServerError)
	u := Uploader{BaseURL: srv.URL, ProjectID: "1", Token: "t", Client: srv.Client()}
	if _, err := u.Upload("gold", "1.0.0", dir); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("server error: %v", err)
	}
	if _, err := (Uploader{ProjectID: "1", Token: "t"}).Upload("gold", "1.0.0", dir); err == nil {
		t.Error("a missing URL should fail")
	}
	if _, err := (Uploader{BaseURL: srv.URL, ProjectID: "1"}).Upload("gold", "1.0.0", dir); err == nil {
		t.Error("a missing token should fail")
	}
	if _, err := u.Upload("gold", "not-a-version", dir); err == nil {
		t.Error("a bad version should fail")
	}
	if _, err := u.Upload("../etc", "1.0.0", dir); err == nil {
		t.Error("a bad package name should fail")
	}
	if _, err := u.Upload("gold", "1.0.0", t.TempDir()); err == nil {
		t.Error("an empty folder should fail")
	}
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, "has space.txt"), []byte("x"), 0o644)
	if _, err := u.Upload("gold", "1.0.0", bad); err == nil {
		t.Error("an unusual file name should fail")
	}
	unreachable := Uploader{BaseURL: "http://127.0.0.1:1", ProjectID: "1", Token: "t", Client: &http.Client{Timeout: time.Second}}
	if _, err := unreachable.Upload("gold", "1.0.0", dir); err == nil {
		t.Error("an unreachable server should fail")
	}
}

func run(env map[string]string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, func(k string) string { return env[k] }, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunCommands(t *testing.T) {
	if code, out, _ := run(nil, "version-from-tag", "--prefix", "gold-v", "--tag", "gold-v0.3.1"); code != 0 || out != "0.3.1\n" {
		t.Errorf("version-from-tag: %d %q", code, out)
	}
	if code, _, errs := run(nil, "version-from-tag", "--prefix", "gold-v", "--tag", "main"); code != 1 || !strings.Contains(errs, "MAJOR.MINOR.PATCH") {
		t.Errorf("bad tag: %d %q", code, errs)
	}
	if code, _, _ := run(nil); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code, _, _ := run(nil, "frobnicate"); code != 2 {
		t.Errorf("unknown command: %d", code)
	}
	if code, _, _ := run(nil, "build"); code != 2 {
		t.Errorf("build without version: %d", code)
	}
	if code, _, _ := run(nil, "build", "--version", "1.0.0", "--targets", "linux"); code != 2 {
		t.Errorf("bad targets: %d", code)
	}
	if code, _, _ := run(nil, "upload", "--dir", t.TempDir()); code != 2 {
		t.Errorf("upload without version: %d", code)
	}
	if code, _, errs := run(map[string]string{}, "upload", "--dir", t.TempDir(), "--version", "1.0.0"); code != 1 || !strings.Contains(errs, "job token") {
		t.Errorf("upload without CI variables: %d %q", code, errs)
	}
	if code, _, _ := run(nil, "verify", "--dir", t.TempDir()); code != 1 {
		t.Errorf("verify empty: %d", code)
	}
	if code, out, _ := run(nil, "help"); code != 0 || !strings.Contains(out, "release build") {
		t.Errorf("help: %d", code)
	}
}

func TestRunBuildVerifyUploadEndToEnd(t *testing.T) {
	out := t.TempDir()
	env := map[string]string{}
	srv, got := registry(t, http.StatusCreated)
	env["CI_API_V4_URL"], env["CI_PROJECT_ID"], env["CI_JOB_TOKEN"] = srv.URL+"/api/v4", "7", "tok"
	target := host().String()
	if code, _, errs := run(env, "build", "--module", moduleDir, "--version", "0.0.1", "--out", out, "--targets", target); code != 0 {
		t.Fatalf("build: %d %s", code, errs)
	}
	if code, _, errs := run(env, "verify", "--dir", out); code != 0 {
		t.Fatalf("verify: %d %s", code, errs)
	}
	if code, msg, errs := run(env, "upload", "--dir", out, "--package", "gold", "--version", "0.0.1"); code != 0 || !strings.Contains(msg, "uploaded 2 files") {
		t.Fatalf("upload: %d %q %s", code, msg, errs)
	}
	if len(*got) != 2 {
		t.Errorf("want 2 uploads, got %d", len(*got))
	}
}

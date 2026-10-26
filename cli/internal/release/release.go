// Package release builds, checks and publishes gold release archives. It is
// what the release pipeline runs, kept as ordinary tested Go code so nothing
// the pipeline does depends on an untracked script.
package release

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ChecksumsFile is the name of the checksums file next to the archives.
const ChecksumsFile = "checksums.txt"

var (
	tagVersion   = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	buildVersion = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	fileName     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Target is an operating system and CPU architecture.
type Target struct{ OS, Arch string }

func (t Target) String() string { return t.OS + "/" + t.Arch }

// DefaultTargets are the platforms gold is released for.
func DefaultTargets() []Target {
	return []Target{
		{"linux", "amd64"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"},
		{"windows", "amd64"}, {"windows", "arm64"},
	}
}

// uniqueTargets drops repeated targets, keeping the first of each, because two
// builds for one target would write the same archive twice.
func uniqueTargets(in []Target) []Target {
	seen := map[Target]bool{}
	var out []Target
	for _, t := range in {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// ParseTargets reads a comma-separated list such as "linux/amd64,darwin/arm64".
func ParseTargets(s string) ([]Target, error) {
	var out []Target
	for _, part := range strings.Split(s, ",") {
		os, arch, ok := strings.Cut(strings.TrimSpace(part), "/")
		if !ok || os == "" || arch == "" {
			return nil, fmt.Errorf("target %q must look like os/arch", part)
		}
		out = append(out, Target{os, arch})
	}
	return out, nil
}

// VersionFromTag turns a release tag such as gold-v1.2.3 into 1.2.3.
func VersionFromTag(prefix, tag string) (string, error) {
	version, ok := strings.CutPrefix(tag, prefix)
	if !ok || !tagVersion.MatchString(version) {
		return "", fmt.Errorf("tag %q must be %sMAJOR.MINOR.PATCH", tag, prefix)
	}
	return version, nil
}

// ArchiveName is the file name of the archive for a target.
func ArchiveName(binary string, t Target) string {
	ext := ".tar.gz"
	if t.OS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("%s_%s_%s%s", binary, t.OS, t.Arch, ext)
}

// BuildOptions say what to build.
type BuildOptions struct {
	ModuleDir string   // folder holding go.mod
	Package   string   // package to build, default "."
	Binary    string   // program name, default "gold"
	Version   string   // stamped into main.version
	Out       string   // folder for the archives and checksums
	Targets   []Target // default: DefaultTargets
	Env       []string // extra environment for the go command
}

// Build compiles one binary per target, wraps each in a reproducible archive,
// and writes the checksums file. It returns the archive names.
func Build(o BuildOptions) ([]string, error) {
	if !buildVersion.MatchString(o.Version) {
		return nil, fmt.Errorf("version %q must look like 1.2.3", o.Version)
	}
	if o.Package == "" {
		o.Package = "."
	}
	if o.Binary == "" {
		o.Binary = "gold"
	}
	if len(o.Targets) == 0 {
		o.Targets = DefaultTargets()
	}
	o.Targets = uniqueTargets(o.Targets)
	if err := os.MkdirAll(o.Out, 0o755); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp("", "gold-build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	var names []string
	for _, t := range o.Targets {
		exe := o.Binary
		if t.OS == "windows" {
			exe += ".exe"
		}
		bin := filepath.Join(work, t.OS+"_"+t.Arch, exe)
		cmd := exec.Command("go", "build", "-trimpath", "-buildvcs=false",
			"-ldflags", "-s -w -X main.version="+o.Version, "-o", bin, o.Package)
		cmd.Dir = o.ModuleDir
		cmd.Env = append(append(os.Environ(), "CGO_ENABLED=0", "GOOS="+t.OS, "GOARCH="+t.Arch, "GOFLAGS=-mod=readonly"), o.Env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("build %s: %v\n%s", t, err, out)
		}
		name := ArchiveName(o.Binary, t)
		if err := writeArchive(filepath.Join(o.Out, name), bin, exe, t.OS == "windows"); err != nil {
			return nil, fmt.Errorf("archive %s: %w", t, err)
		}
		names = append(names, name)
	}
	return names, WriteChecksums(o.Out)
}

var epoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// writeArchive stores one executable with no timestamps or owners, so the same
// binary always gives the same archive bytes.
func writeArchive(dest, binPath, exe string, asZip bool) error {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if asZip {
		zw := zip.NewWriter(&buf)
		h := &zip.FileHeader{Name: exe, Method: zip.Deflate, Modified: epoch}
		h.SetMode(0o755)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
	} else {
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		hdr := &tar.Header{Name: exe, Mode: 0o755, Size: int64(len(data)), ModTime: epoch, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
		if err := tw.Close(); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
	}
	return os.WriteFile(dest, buf.Bytes(), 0o644)
}

func isArchive(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".zip")
}

func sum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func archives(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && isArchive(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// WriteChecksums writes checksums.txt for every archive in dir, in the format
// "sha256sum -c" reads.
func WriteChecksums(dir string) error {
	names, err := archives(dir)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("no archives to checksum in " + dir)
	}
	var b strings.Builder
	for _, n := range names {
		s, err := sum(filepath.Join(dir, n))
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s  %s\n", s, n)
	}
	return os.WriteFile(filepath.Join(dir, ChecksumsFile), []byte(b.String()), 0o644)
}

// VerifyChecksums recomputes every checksum. It fails on a changed or missing
// archive, and on an archive that the checksums file does not list.
func VerifyChecksums(dir string) error {
	f, err := os.Open(filepath.Join(dir, ChecksumsFile))
	if err != nil {
		return err
	}
	defer f.Close()
	listed := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		want, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok || !fileName.MatchString(name) || len(want) != 64 {
			return fmt.Errorf("%s: malformed line %q", ChecksumsFile, sc.Text())
		}
		got, err := sum(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("%s: checksum mismatch", name)
		}
		listed[name] = true
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if len(listed) == 0 {
		return fmt.Errorf("%s lists no files", ChecksumsFile)
	}
	names, err := archives(dir)
	if err != nil {
		return err
	}
	for _, n := range names {
		if !listed[n] {
			return fmt.Errorf("%s is not listed in %s", n, ChecksumsFile)
		}
	}
	return nil
}

// Uploader publishes files to a GitLab generic package.
type Uploader struct {
	BaseURL   string // for example https://gitlab.com/api/v4
	ProjectID string
	Token     string // a CI job token
	Client    *http.Client
}

// Upload sends every regular file in dir to package/version and returns the names.
func (u Uploader) Upload(pkg, version, dir string) ([]string, error) {
	if u.BaseURL == "" || u.ProjectID == "" || u.Token == "" {
		return nil, errors.New("upload needs the API URL, project ID and a job token")
	}
	if !fileName.MatchString(pkg) || !buildVersion.MatchString(version) {
		return nil, fmt.Errorf("package %q and version %q aren't valid", pkg, version)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	var sent []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if !fileName.MatchString(e.Name()) {
			return nil, fmt.Errorf("file name %q isn't allowed in a package", e.Name())
		}
		if err := u.put(client, pkg, version, filepath.Join(dir, e.Name()), e.Name()); err != nil {
			return sent, err
		}
		sent = append(sent, e.Name())
	}
	if len(sent) == 0 {
		return nil, errors.New("nothing to upload in " + dir)
	}
	return sent, nil
}

func (u Uploader) put(c *http.Client, pkg, version, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/projects/%s/packages/generic/%s/%s/%s", strings.TrimRight(u.BaseURL, "/"), u.ProjectID, pkg, version, name)
	req, err := http.NewRequest(http.MethodPut, url, f)
	if err != nil {
		return err
	}
	req.ContentLength = info.Size()
	req.Header.Set("JOB-TOKEN", u.Token)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("upload %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("upload %s: HTTP %d %s", name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

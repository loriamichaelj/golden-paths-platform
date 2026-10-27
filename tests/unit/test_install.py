"""Tests for install.py. Downloads and subprocesses are injected, so nothing
touches the network. One test signs with a real cosign when it is available."""

import hashlib
import importlib.util
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
spec = importlib.util.spec_from_file_location("install", os.path.join(ROOT, "install.py"))
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)

API = "https://registry.example.com/api/v4"
PROJECT = "group/project"
BASE = f"{API}/projects/group%2Fproject"


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def tar_gz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_of(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def release(version="1.2.3", binary=b"#!/bin/sh\necho gold\n", targets=(("darwin", "arm64"), ("linux", "amd64"), ("windows", "amd64"))):
    """A fake release: file URL -> bytes, as the registry would serve it."""
    files, lines = {}, []
    for os_name, arch in targets:
        name = f"gold_{os_name}_{arch}.{'zip' if os_name == 'windows' else 'tar.gz'}"
        data = zip_of([("gold.exe", binary)]) if os_name == "windows" else tar_gz([("gold", binary)])
        files[name] = data
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    files["checksums.txt"] = ("\n".join(sorted(lines, key=lambda l: l.split("  ")[1])) + "\n").encode()
    files["checksums.txt.sigstore.json"] = b'{"fake": "bundle"}'
    return {f"{BASE}/packages/generic/gold/{version}/{n}": d for n, d in files.items()}


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def make(files, run=None, which=None, token=""):
    calls = []

    def fetch(url):
        calls.append(url)
        if url not in files:
            raise install.InstallError(f"download failed: HTTP 404 for {url}")
        return files[url]

    out, err = io.StringIO(), io.StringIO()
    inst = install.Installer(API, PROJECT, token, fetch=fetch, run=run or (lambda cmd, **kw: FakeProc()),
                             which=which or (lambda name: "/usr/bin/cosign"), stdout=out, stderr=err)
    return inst, calls, out, err


class Base(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.tmp = t.name
        self.bin = os.path.join(self.tmp, "bin")


class PureFunctionTests(unittest.TestCase):
    def test_platform_names(self):
        for system, machine, want in [
            ("darwin", "arm64", ("darwin", "arm64")), ("darwin", "x86_64", ("darwin", "amd64")),
            ("linux", "x86_64", ("linux", "amd64")), ("linux", "aarch64", ("linux", "arm64")),
            ("win32", "AMD64", ("windows", "amd64")), ("win32", "ARM64", ("windows", "arm64")),
        ]:
            self.assertEqual(install.detect_platform(system, machine), want)
        for bad in [("freebsd", "x86_64"), ("linux", "riscv64"), ("sunos", "sparc")]:
            with self.assertRaises(install.InstallError):
                install.detect_platform(*bad)

    def test_latest_version_ignores_prereleases_and_compares_numbers(self):
        self.assertEqual(install.latest_version(["1.2.9", "1.2.10", "1.10.0", "0.0.0-ci", "1.9.99", "", "latest"]), "1.10.0")
        with self.assertRaises(install.InstallError):
            install.latest_version(["0.0.0-ci", "junk"])

    def test_checksum_parsing(self):
        good = "a" * 64 + "  gold_linux_amd64.tar.gz\n" + "b" * 64 + "  checksums-extra.txt\n"
        self.assertEqual(set(install.parse_checksums(good)), {"gold_linux_amd64.tar.gz", "checksums-extra.txt"})
        for bad in ["", "nothex  file.tar.gz\n", "a" * 64 + " one-space.tar.gz\n", "a" * 64 + "  ../escape\n", "a" * 63 + "  short\n"]:
            with self.assertRaises(install.InstallError, msg=bad):
                install.parse_checksums(bad)

    def test_extraction_accepts_exactly_one_expected_file(self):
        self.assertEqual(install.extract_binary(tar_gz([("gold", b"x")]), "g.tar.gz", "gold"), b"x")
        self.assertEqual(install.extract_binary(zip_of([("gold.exe", b"y")]), "g.zip", "gold.exe"), b"y")

    def test_extraction_rejects_anything_else(self):
        for label, archive, name, binary in [
            ("path traversal", tar_gz([("../evil", b"x")]), "g.tar.gz", "gold"),
            ("absolute path", tar_gz([("/etc/passwd", b"x")]), "g.tar.gz", "gold"),
            ("extra file", tar_gz([("gold", b"x"), ("other", b"y")]), "g.tar.gz", "gold"),
            ("wrong name", tar_gz([("not-gold", b"x")]), "g.tar.gz", "gold"),
            ("nested", tar_gz([("dir/gold", b"x")]), "g.tar.gz", "gold"),
            ("zip traversal", zip_of([("../evil.exe", b"x")]), "g.zip", "gold.exe"),
            ("zip extra", zip_of([("gold.exe", b"x"), ("a.txt", b"y")]), "g.zip", "gold.exe"),
            ("not an archive", b"plain bytes", "g.tar.gz", "gold"),
            ("not a zip", b"plain bytes", "g.zip", "gold.exe"),
        ]:
            with self.subTest(label), self.assertRaises(install.InstallError):
                install.extract_binary(archive, name, binary)

    def test_extraction_rejects_a_symlink_member(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("gold")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        with self.assertRaises(install.InstallError):
            install.extract_binary(buf.getvalue(), "g.tar.gz", "gold")

    def test_the_embedded_key_is_the_published_one(self):
        with open(os.path.join(ROOT, "keys", "cosign.pub")) as fh:
            self.assertEqual(install.PUBLIC_KEY, fh.read())


class InstallTests(Base):
    def test_happy_path_installs_a_working_executable(self):
        inst, calls, out, _ = make(release())
        dest = inst.install("1.2.3", self.bin, system="linux", machine="x86_64")
        self.assertEqual(dest, os.path.join(self.bin, "gold"))
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), b"#!/bin/sh\necho gold\n")
        self.assertTrue(os.access(dest, os.X_OK))
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o755)
        self.assertIn("signature verified", out.getvalue())
        self.assertIn("checksum verified", out.getvalue())
        self.assertEqual(os.listdir(self.bin), ["gold"], "no temporary files may be left behind")
        self.assertEqual([u.rsplit("/", 1)[1] for u in calls], ["checksums.txt", "checksums.txt.sigstore.json", "gold_linux_amd64.tar.gz"])

    def test_windows_gets_the_zip_and_an_exe(self):
        inst, calls, _, _ = make(release())
        dest = inst.install("1.2.3", self.bin, system="win32", machine="AMD64")
        self.assertEqual(os.path.basename(dest), "gold.exe")
        self.assertTrue(calls[-1].endswith("gold_windows_amd64.zip"))

    def test_latest_is_found_through_the_package_listing(self):
        files = release("1.2.3")
        files.update(release("1.10.0", binary=b"newer"))
        listing = [{"name": "gold", "version": v} for v in ("1.2.3", "1.10.0", "0.0.0-ci")] + [{"name": "other", "version": "9.9.9"}]
        import json
        files[f"{BASE}/packages?package_type=generic&package_name=gold&per_page=100"] = json.dumps(listing).encode()
        inst, _, _, _ = make(files)
        dest = inst.install(None, self.bin, system="linux", machine="x86_64")
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), b"newer")

    def test_a_bad_checksum_installs_nothing_and_keeps_the_old_binary(self):
        files = release()
        key = f"{BASE}/packages/generic/gold/1.2.3/gold_linux_amd64.tar.gz"
        files[key] = tar_gz([("gold", b"tampered")])
        os.makedirs(self.bin)
        with open(os.path.join(self.bin, "gold"), "wb") as fh:
            fh.write(b"old")
        inst, _, _, _ = make(files)
        with self.assertRaisesRegex(install.InstallError, "does not match its checksum"):
            inst.install("1.2.3", self.bin, system="linux", machine="x86_64")
        with open(os.path.join(self.bin, "gold"), "rb") as fh:
            self.assertEqual(fh.read(), b"old")
        self.assertEqual(os.listdir(self.bin), ["gold"])

    def test_a_failed_signature_installs_nothing_and_downloads_no_archive(self):
        inst, calls, _, _ = make(release(), run=lambda cmd, **kw: FakeProc(1, stderr="invalid signature"))
        with self.assertRaisesRegex(install.InstallError, "signature did not verify"):
            inst.install("1.2.3", self.bin, system="linux", machine="x86_64")
        self.assertFalse(os.path.exists(os.path.join(self.bin, "gold")))
        self.assertFalse(any(u.endswith(".tar.gz") for u in calls), "the archive must not be fetched before the signature checks out")

    def test_cosign_is_called_with_the_key_bundle_and_checksums(self):
        seen = {}

        def run(cmd, **kw):
            seen["cmd"] = cmd
            seen["files"] = {os.path.basename(p): read(p) for p in cmd if os.path.isfile(p)}
            return FakeProc()

        files = release()
        inst, _, _, _ = make(files, run=run)
        inst.install("1.2.3", self.bin, system="linux", machine="x86_64")
        cmd = seen["cmd"]
        self.assertEqual(cmd[:2], ["/usr/bin/cosign", "verify-blob"])
        for flag in ("--key", "--bundle", "--insecure-ignore-tlog=true"):
            self.assertIn(flag, cmd)
        self.assertEqual(seen["files"]["cosign.pub"].decode(), install.PUBLIC_KEY)
        self.assertEqual(seen["files"]["checksums.txt"], files[f"{BASE}/packages/generic/gold/1.2.3/checksums.txt"])
        self.assertEqual(seen["files"]["checksums.txt.sigstore.json"], b'{"fake": "bundle"}')

    def test_without_cosign_it_stops_unless_told_otherwise(self):
        inst, _, _, _ = make(release(), which=lambda name: None)
        with self.assertRaisesRegex(install.InstallError, "cosign is needed"):
            inst.install("1.2.3", self.bin, system="linux", machine="x86_64")
        self.assertFalse(os.path.exists(self.bin) and os.listdir(self.bin))

        inst, _, out, err = make(release(), which=lambda name: None)
        dest = inst.install("1.2.3", self.bin, verify_signature=False, system="linux", machine="x86_64")
        self.assertTrue(os.path.exists(dest))
        self.assertIn("WARNING: signature not checked", err.getvalue())
        self.assertNotIn("signature verified", out.getvalue())

    def test_missing_platform_or_bad_version(self):
        inst, _, _, _ = make(release(targets=(("linux", "amd64"),)))
        with self.assertRaisesRegex(install.InstallError, "has no gold_darwin_arm64.tar.gz"):
            inst.install("1.2.3", self.bin, system="darwin", machine="arm64")
        for v in ("1.2", "v1.2.3", "1.2.3; rm -rf /", "../1.2.3"):
            with self.subTest(v), self.assertRaises(install.InstallError):
                inst.install(v, self.bin, system="linux", machine="x86_64")

    def test_the_token_is_sent_and_never_printed(self):
        secret = "glpat-SECRET-VALUE"
        inst = install.Installer(API, PROJECT, secret, stdout=io.StringIO(), stderr=io.StringIO())
        self.assertEqual(inst._auth_headers(), {"PRIVATE-TOKEN": secret})
        self.assertEqual(install.Installer(API, PROJECT, "")._auth_headers(), {})
        self.assertNotIn(secret, inst._redact(f"failed for {BASE}?private_token={secret}"))

    def test_an_unwritable_folder_is_a_clear_error(self):
        blocker = os.path.join(self.tmp, "file")
        open(blocker, "w").close()
        inst, _, _, _ = make(release())
        with self.assertRaises((install.InstallError, OSError)):
            inst.install("1.2.3", os.path.join(blocker, "sub"), system="linux", machine="x86_64")


class MainTests(Base):
    def run_main(self, argv, installer, env=None):
        out, err = installer.out, installer.err
        code = install.main(argv, env=env or {}, installer=installer)
        return code, out.getvalue(), err.getvalue()

    def test_main_installs_and_reports(self):
        inst, _, _, _ = make(release())
        orig = install.detect_platform
        install.detect_platform = lambda s=None, m=None: ("linux", "amd64")
        self.addCleanup(setattr, install, "detect_platform", orig)
        code, out, err = self.run_main(["--version", "1.2.3", "--dir", self.bin], inst)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("installed", out)

    def test_main_reports_failures_with_exit_1(self):
        inst, _, _, _ = make({})
        code, _, err = self.run_main(["--version", "1.2.3", "--dir", self.bin], inst)
        self.assertEqual(code, 1)
        self.assertIn("install: ", err)

    def test_with_skill_runs_gold_skill_install(self):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            return FakeProc(0, stdout="installed the golden-path skill")

        inst, _, _, _ = make(release(), run=run)
        orig = install.detect_platform
        install.detect_platform = lambda s=None, m=None: ("linux", "amd64")
        self.addCleanup(setattr, install, "detect_platform", orig)
        code, out, _ = self.run_main(["--version", "1.2.3", "--dir", self.bin, "--with-skill", "--skill-scope", "project"], inst)
        self.assertEqual(code, 0)
        self.assertEqual(calls[-1], [os.path.join(self.bin, "gold"), "skill", "install", "--scope", "project"])
        self.assertIn("installed the golden-path skill", out)

    def test_a_failing_skill_install_is_reported(self):
        def run(cmd, **kw):
            return FakeProc(2, stderr="boom") if "skill" in cmd else FakeProc()

        inst, _, _, _ = make(release(), run=run)
        orig = install.detect_platform
        install.detect_platform = lambda s=None, m=None: ("linux", "amd64")
        self.addCleanup(setattr, install, "detect_platform", orig)
        code, _, err = self.run_main(["--version", "1.2.3", "--dir", self.bin, "--with-skill"], inst)
        self.assertEqual(code, 1)
        self.assertIn("installing the skill failed: boom", err)


def find_cosign():
    for candidate in (os.environ.get("GOLD_COSIGN"), shutil.which("cosign"), os.path.join(ROOT, "..", ".tools", "bin", "cosign")):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


@unittest.skipUnless(find_cosign(), "cosign is not installed")
class RealSignatureTests(Base):
    """Sign a release with a throwaway key and run the real cosign over it."""

    def setUp(self):
        super().setUp()
        self.cosign = find_cosign()
        self.env = {**os.environ, "COSIGN_PASSWORD": "x"}
        subprocess.run([self.cosign, "generate-key-pair"], cwd=self.tmp, env=self.env, capture_output=True, check=True)
        self.files = release()
        sums = self.files[f"{BASE}/packages/generic/gold/1.2.3/checksums.txt"]
        with open(os.path.join(self.tmp, "checksums.txt"), "wb") as fh:
            fh.write(sums)
        subprocess.run([self.cosign, "sign-blob", "--yes", "--key", "cosign.key", "--use-signing-config=false", "--tlog-upload=false",
                        "--bundle", "bundle.json", "checksums.txt"], cwd=self.tmp, env=self.env, capture_output=True, check=True)
        with open(os.path.join(self.tmp, "bundle.json"), "rb") as fh:
            self.files[f"{BASE}/packages/generic/gold/1.2.3/checksums.txt.sigstore.json"] = fh.read()
        with open(os.path.join(self.tmp, "cosign.pub")) as fh:
            self.pub = fh.read()

    def real_installer(self, files):
        inst, _, out, err = make(files, run=lambda cmd, **kw: subprocess.run(cmd, **kw))
        return inst

    def test_a_genuine_signature_installs(self):
        dest = self.real_installer(self.files).install("1.2.3", self.bin, public_key=self.pub, cosign=self.cosign, system="linux", machine="x86_64")
        self.assertTrue(os.path.exists(dest))

    def test_the_wrong_key_is_rejected(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other)
        subprocess.run([self.cosign, "generate-key-pair"], cwd=other, env=self.env, capture_output=True, check=True)
        with open(os.path.join(other, "cosign.pub")) as fh:
            wrong = fh.read()
        with self.assertRaisesRegex(install.InstallError, "signature did not verify"):
            self.real_installer(self.files).install("1.2.3", self.bin, public_key=wrong, cosign=self.cosign, system="linux", machine="x86_64")
        self.assertFalse(os.path.exists(os.path.join(self.bin, "gold")))

    def test_changed_checksums_break_the_signature(self):
        files = dict(self.files)
        key = f"{BASE}/packages/generic/gold/1.2.3/checksums.txt"
        files[key] = files[key].replace(b"a", b"b", 1) if b"a" in files[key] else files[key] + b"\n# changed\n"
        with self.assertRaisesRegex(install.InstallError, "signature did not verify"):
            self.real_installer(files).install("1.2.3", self.bin, public_key=self.pub, cosign=self.cosign, system="linux", machine="x86_64")


if __name__ == "__main__":
    unittest.main()

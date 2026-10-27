#!/usr/bin/env python3
"""Install the gold command-line tool from a signed release.

    python3 install.py [--version 1.2.3] [--dir ~/.local/bin] [--with-skill]

The installer downloads the archive for this machine, checks its SHA-256 against
the release's checksums file, verifies the signature on that file with cosign
and the public key below, and only then replaces the installed binary. If any
step fails, nothing is installed and any existing gold is left untouched.

The release package may need a token: set GOLD_TOKEN (or GITLAB_TOKEN) to a
personal access token that can read the project's packages.

Without cosign the installer stops. Pass --no-verify-signature to install on
the checksum alone; that proves the download is intact, not who published it.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

DEFAULT_API = "https://gitlab.com/api/v4"
DEFAULT_PROJECT = "michaeljloria/golden-paths-platform"
PACKAGE = "gold"

# The key that signs every release (keys/cosign.pub in the repository).
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEafRnN493UmoTeVySRaAYcrombCZK
vGVSLGHwH/DOP9G9oP3pNH+5K7ekrlVEzc9xFXI4vDAp88hNO71EwITEgw==
-----END PUBLIC KEY-----
"""

RELEASE_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
MAX_BINARY_BYTES = 200 * 1024 * 1024


class InstallError(Exception):
    """A step failed; the message says what to do about it."""


def detect_platform(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    """Return the (os, arch) names the release archives use."""
    system = (system or sys.platform).lower()
    machine = (machine or platform.machine()).lower()
    os_name = {"darwin": "darwin", "linux": "linux", "win32": "windows", "cygwin": "windows", "msys": "windows"}.get(system)
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if not os_name or not arch:
        raise InstallError(f"no release is published for {system}/{machine}")
    return os_name, arch


def version_key(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def latest_version(versions: list[str]) -> str:
    """The highest MAJOR.MINOR.PATCH release; pre-releases and CI builds are ignored."""
    releases = [v for v in versions if RELEASE_VERSION.match(v)]
    if not releases:
        raise InstallError("the package registry has no gold release yet")
    return max(releases, key=version_key)


def parse_checksums(text: str) -> dict[str, str]:
    sums: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        if not sep or not re.fullmatch(r"[0-9a-f]{64}", digest) or not re.fullmatch(r"[A-Za-z0-9._-]+", name):
            raise InstallError(f"checksums.txt has a malformed line: {line!r}")
        sums[name] = digest
    if not sums:
        raise InstallError("checksums.txt lists no files")
    return sums


def extract_binary(archive: bytes, archive_name: str, binary: str) -> bytes:
    """Return the executable from an archive that holds exactly that one file."""
    try:
        if archive_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                infos = zf.infolist()
                if [i.filename for i in infos] != [binary]:
                    raise InstallError(f"{archive_name} must contain only {binary}")
                if infos[0].file_size > MAX_BINARY_BYTES:
                    raise InstallError(f"{archive_name} holds an unreasonably large file")
                return zf.read(infos[0])
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
            members = tf.getmembers()
            if len(members) != 1 or members[0].name != binary or not members[0].isreg():
                raise InstallError(f"{archive_name} must contain only {binary}")
            if members[0].size > MAX_BINARY_BYTES:
                raise InstallError(f"{archive_name} holds an unreasonably large file")
            f = tf.extractfile(members[0])
            assert f is not None
            return f.read()
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError) as e:
        raise InstallError(f"cannot read {archive_name}: {e}") from e


class Installer:
    def __init__(self, api: str = DEFAULT_API, project: str = DEFAULT_PROJECT, token: str = "",
                 fetch=None, run=None, which=None, stdout=None, stderr=None):
        self.api, self.project, self.token = api.rstrip("/"), project, token
        self._fetch = fetch or self._http_get
        self._run = run or (lambda cmd, **kw: subprocess.run(cmd, **kw))
        self._which = which or shutil.which
        self.out, self.err = stdout or sys.stdout, stderr or sys.stderr

    # ---- network ----
    def _http_get(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers=self._auth_headers())
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            hint = ""
            if e.code in (401, 403, 404) and not self.token:
                hint = " (the project may be private: set GOLD_TOKEN to a token that can read its packages)"
            raise InstallError(f"download failed: HTTP {e.code} for {self._redact(url)}{hint}") from e
        except urllib.error.URLError as e:
            raise InstallError(f"download failed: {e.reason}") from e

    def _auth_headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self.token} if self.token else {}

    def _redact(self, text: str) -> str:
        return text.replace(self.token, "***") if self.token else text

    def _project_url(self) -> str:
        return f"{self.api}/projects/{urllib.parse.quote(self.project, safe='')}"

    def _get(self, url: str) -> bytes:
        return self._fetch(url)

    def find_latest(self) -> str:
        url = f"{self._project_url()}/packages?package_type=generic&package_name={PACKAGE}&per_page=100"
        try:
            listing = json.loads(self._get(url))
        except json.JSONDecodeError as e:
            raise InstallError("the package registry returned something unreadable") from e
        return latest_version([p.get("version", "") for p in listing if p.get("name") == PACKAGE])

    def _file_url(self, version: str, name: str) -> str:
        return f"{self._project_url()}/packages/generic/{PACKAGE}/{version}/{name}"

    # ---- verification ----
    def verify_signature(self, checksums: bytes, bundle: bytes, public_key: str, cosign: str | None) -> None:
        cosign = cosign or self._which("cosign")
        if not cosign:
            raise InstallError("cosign is needed to verify the release signature; install it, or pass --no-verify-signature to rely on the checksum alone")
        with tempfile.TemporaryDirectory() as tmp:
            paths = {"key": "cosign.pub", "sums": "checksums.txt", "bundle": "checksums.txt.sigstore.json"}
            for key, data in (("key", public_key.encode()), ("sums", checksums), ("bundle", bundle)):
                with open(os.path.join(tmp, paths[key]), "wb") as fh:
                    fh.write(data)
            proc = self._run(
                [cosign, "verify-blob", "--key", os.path.join(tmp, paths["key"]), "--bundle", os.path.join(tmp, paths["bundle"]),
                 "--insecure-ignore-tlog=true", os.path.join(tmp, paths["sums"])],
                capture_output=True, text=True)
        if proc.returncode != 0:
            raise InstallError("the release signature did not verify; nothing was installed.\n" + (proc.stderr or "").strip()[-300:])

    # ---- the install ----
    def install(self, version: str | None, target_dir: str, verify_signature: bool = True,
                public_key: str = PUBLIC_KEY, cosign: str | None = None, system: str | None = None,
                machine: str | None = None) -> str:
        os_name, arch = detect_platform(system, machine)
        version = version or self.find_latest()
        if not RELEASE_VERSION.match(version):
            raise InstallError(f"version {version!r} must look like 1.2.3")
        ext = "zip" if os_name == "windows" else "tar.gz"
        archive_name = f"gold_{os_name}_{arch}.{ext}"
        binary = "gold.exe" if os_name == "windows" else "gold"

        print(f"installing gold {version} for {os_name}/{arch}", file=self.out)
        checksums = self._get(self._file_url(version, "checksums.txt"))
        sums = parse_checksums(checksums.decode("utf-8", "replace"))
        if archive_name not in sums:
            raise InstallError(f"release {version} has no {archive_name}")

        if verify_signature:
            bundle = self._get(self._file_url(version, "checksums.txt.sigstore.json"))
            self.verify_signature(checksums, bundle, public_key, cosign)
            print("signature verified", file=self.out)
        else:
            print("WARNING: signature not checked; the checksum proves the download is intact, not who published it", file=self.err)

        archive = self._get(self._file_url(version, archive_name))
        if hashlib.sha256(archive).hexdigest() != sums[archive_name]:
            raise InstallError(f"{archive_name} does not match its checksum; nothing was installed")
        print("checksum verified", file=self.out)

        data = extract_binary(archive, archive_name, binary)
        os.makedirs(target_dir, exist_ok=True)
        dest = os.path.join(target_dir, binary)
        fd, tmp = tempfile.mkstemp(prefix=".gold-install-", dir=target_dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o755)
            os.replace(tmp, dest)
        except OSError as e:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise InstallError(f"cannot write {dest}: {e.strerror or e}") from e
        print(f"installed {dest}", file=self.out)
        if os.path.abspath(target_dir) not in [os.path.abspath(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p]:
            print(f"note: {target_dir} is not on your PATH", file=self.out)
        return dest


def main(argv: list[str] | None = None, env=None, installer: Installer | None = None) -> int:
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(description="Install gold from a signed release.")
    ap.add_argument("--version", help="release to install, such as 1.2.3 (default: the latest)")
    ap.add_argument("--dir", default=os.path.join("~", ".local", "bin"), help="folder to install into (default: ~/.local/bin)")
    ap.add_argument("--with-skill", action="store_true", help="also install the agent skill that ships inside gold")
    ap.add_argument("--skill-scope", choices=["user", "project"], default="user", help="where --with-skill installs it")
    ap.add_argument("--no-verify-signature", action="store_true", help="rely on the checksum alone (not recommended)")
    ap.add_argument("--cosign", help="path to the cosign program (default: found on PATH)")
    ap.add_argument("--public-key", help="verify with this public key file instead of the built-in one")
    ap.add_argument("--api", default=DEFAULT_API, help=argparse.SUPPRESS)
    ap.add_argument("--project", default=DEFAULT_PROJECT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    token = env.get("GOLD_TOKEN") or env.get("GITLAB_TOKEN") or ""
    inst = installer or Installer(args.api, args.project, token)
    key = PUBLIC_KEY
    try:
        if args.public_key:
            with open(args.public_key, encoding="utf-8") as fh:
                key = fh.read()
        dest = inst.install(args.version, os.path.expanduser(args.dir), not args.no_verify_signature, key, args.cosign)
        if args.with_skill:
            proc = inst._run([dest, "skill", "install", "--scope", args.skill_scope], capture_output=True, text=True)
            if proc.returncode != 0:
                raise InstallError("gold is installed, but installing the skill failed: " + (proc.stderr or proc.stdout).strip())
            print((proc.stdout or "").strip(), file=inst.out)
    except (InstallError, OSError) as e:
        print(f"install: {inst._redact(str(e))}", file=inst.err)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

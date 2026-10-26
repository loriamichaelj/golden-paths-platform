#!/usr/bin/env python3
"""gate.py makes the single pass/fail decision for gold-scan.

Scanners (Trivy, Checkov) only report. This script reads their JSON, applies
the exceptions file, and decides. A finding blocks when it is a secret, or its
severity is HIGH or CRITICAL (Checkov failures count as HIGH). Everything else
is reported and does not block.

Exceptions live in .security/exceptions.yaml. Each needs a check id, a reason,
an owner and an expiry within 180 days. Inline skips (checkov:skip,
trivy:ignore) and ignore files are not allowed, so there is one place to look.

Exit status: 0 the gate passed, 1 it failed, 2 the inputs were unusable. A
scanner report that is missing or unreadable never passes.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from typing import Iterable

import yaml

BLOCKING = {"HIGH", "CRITICAL"}
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_EXCEPTION_DAYS = 180

# A real skip always names a check, so prose that merely mentions the syntax is not flagged.
SKIP_PATTERNS = [
    re.compile(r"checkov\s*:\s*skip\s*=\s*\S", re.I),
    re.compile(r"trivy\s*:\s*ignore\s*:\s*\S", re.I),
    re.compile(r"tfsec\s*:\s*ignore\s*:\s*\S", re.I),
]
IGNORE_FILES = {".trivyignore", ".trivyignore.yaml", ".trivyignore.yml"}
CHECKOV_CONFIGS = {".checkov.yaml", ".checkov.yml"}
SKIP_DIRS = {".git", ".terraform", ".security", "node_modules", "vendor", "__pycache__", ".venv"}
MAX_SCAN_BYTES = 1_000_000


class InputError(Exception):
    """The gate cannot decide because an input is missing or unusable."""


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str
    title: str
    path: str
    line: int
    resource: str
    kind: str  # secret | vulnerability | misconfig | policy
    status: str = "informational"  # blocked | excepted | informational
    exception: str = ""

    @property
    def blocking_class(self) -> bool:
        return self.kind == "secret" or self.severity in BLOCKING

    @property
    def fingerprint(self) -> str:
        raw = f"{self.tool}|{self.rule_id}|{self.path}|{self.resource}|{self.line}"
        return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class Exemption:
    check: str
    reason: str
    owner: str
    expires: datetime.date
    resource: str = ""
    path: str = ""

    def matches(self, f: Finding) -> bool:
        return (
            f.rule_id == self.check
            and (not self.resource or fnmatch.fnmatch(f.resource, self.resource))
            and (not self.path or fnmatch.fnmatch(f.path, self.path))
        )


# ---------------------------------------------------------------- scanner input


def load_json(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as e:
        raise InputError(f"cannot read {path}: {e.strerror or e}") from e
    if not text.strip():
        raise InputError(f"{path} is empty; the scanner may have failed")
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise InputError(f"{path} is not valid JSON: {e}") from e


def norm_severity(value) -> str:
    s = str(value or "").upper()
    return s if s in SEVERITY_RANK else "UNKNOWN"


def parse_trivy(doc, source: str = "trivy") -> list[Finding]:
    if not isinstance(doc, dict) or "SchemaVersion" not in doc:
        raise InputError(f"{source} does not look like Trivy JSON output")
    out: list[Finding] = []
    for result in doc.get("Results") or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            pkg = v.get("PkgName", "")
            out.append(Finding(
                "trivy", v.get("VulnerabilityID", ""), norm_severity(v.get("Severity")),
                f"{pkg} {v.get('InstalledVersion', '')}: {v.get('Title') or v.get('VulnerabilityID', '')}".strip(),
                target, 0, pkg, "vulnerability"))
        for s in result.get("Secrets") or []:
            out.append(Finding(
                "trivy", s.get("RuleID", ""), norm_severity(s.get("Severity")),
                s.get("Title", "secret"), target, int(s.get("StartLine") or 0), "", "secret"))
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            out.append(Finding(
                "trivy", m.get("ID", ""), norm_severity(m.get("Severity")),
                m.get("Title") or m.get("Message", ""), target, int(cause.get("StartLine") or 0),
                cause.get("Resource", ""), "misconfig"))
    return out


def _is_checkov(d) -> bool:
    """A results document, or the bare summary Checkov prints when it found nothing to scan."""
    return isinstance(d, dict) and ("results" in d or "summary" in d or ("checkov_version" in d and "failed" in d))


def checkov_problems(doc, source: str = "checkov") -> list[str]:
    """Files Checkov could not parse; they were not scanned, so they cannot pass silently."""
    problems: list[str] = []
    for d in doc if isinstance(doc, list) else [doc]:
        if not isinstance(d, dict):
            continue
        for f in (d.get("results") or {}).get("parsing_errors") or []:
            problems.append(f"{source}: checkov could not parse {f}")
        n = d.get("parsing_errors")
        if isinstance(n, int) and n > 0:
            problems.append(f"{source}: checkov could not parse {n} file(s)")
    return problems


def parse_checkov(doc, source: str = "checkov") -> list[Finding]:
    docs = doc if isinstance(doc, list) else [doc]
    out: list[Finding] = []
    for d in docs:
        if not _is_checkov(d):
            raise InputError(f"{source} does not look like Checkov JSON output")
        for c in (d.get("results") or {}).get("failed_checks") or []:
            lines = c.get("file_line_range") or [0]
            out.append(Finding(
                "checkov", c.get("check_id", ""),
                "HIGH" if not c.get("severity") else norm_severity(c.get("severity")),
                c.get("check_name", ""), (c.get("file_path") or "").lstrip("/"),
                int(lines[0] or 0), c.get("resource", ""), "policy"))
    return out


# ------------------------------------------------------------------- exceptions


def _date(value) -> datetime.date | None:
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    try:
        return datetime.date.fromisoformat(str(value))
    except ValueError:
        return None


def load_exceptions(path: str | None, today: datetime.date, max_days: int) -> tuple[list[Exemption], list[str]]:
    """Return the usable exceptions and a list of problems with the others."""
    if not path or not os.path.exists(path):
        return [], []
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as e:
        raise InputError(f"cannot read exceptions file {path}: {e}") from e
    if doc is None:
        return [], []
    if not isinstance(doc, dict) or not isinstance(doc.get("exceptions") or [], list):
        raise InputError(f"{path} must hold a list under the key 'exceptions'")

    usable: list[Exemption] = []
    problems: list[str] = []
    for i, item in enumerate(doc.get("exceptions") or []):
        label = f"{path}: exceptions[{i}]"
        if not isinstance(item, dict):
            problems.append(f"{label} must be a mapping")
            continue
        check = str(item.get("check") or "").strip()
        label += f" ({check or 'no check'})"
        missing = [k for k in ("check", "reason", "owner", "expires") if not str(item.get(k) or "").strip()]
        if missing:
            problems.append(f"{label} is missing {', '.join(missing)}")
            continue
        expires = _date(item["expires"])
        if expires is None:
            problems.append(f"{label} has an expiry that is not a date: {item['expires']!r}")
        elif expires < today:
            problems.append(f"{label} expired on {expires}; renew it or fix the finding")
        elif expires > today + datetime.timedelta(days=max_days):
            problems.append(f"{label} expires {expires}, more than {max_days} days out")
        else:
            usable.append(Exemption(check, str(item["reason"]).strip(), str(item["owner"]).strip(), expires,
                                    str(item.get("resource") or ""), str(item.get("path") or "")))
    return usable, problems


# ------------------------------------------------------------------ inline skips


def find_skips(root: str) -> list[str]:
    """List inline skips and ignore files under root; none are allowed."""
    problems: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if name in IGNORE_FILES:
                problems.append(f"{rel}: ignore files are not allowed; use .security/exceptions.yaml")
                continue
            try:
                if os.path.getsize(full) > MAX_SCAN_BYTES or os.path.islink(full):
                    continue
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            if name in CHECKOV_CONFIGS and "skip-check" in text:
                problems.append(f"{rel}: skip-check is not allowed; use .security/exceptions.yaml")
            for n, line in enumerate(text.splitlines(), 1):
                if any(p.search(line) for p in SKIP_PATTERNS):
                    problems.append(f"{rel}:{n}: inline skips are not allowed; use .security/exceptions.yaml")
    return problems


# --------------------------------------------------------------------- decision


def decide(findings: Iterable[Finding], exemptions: list[Exemption]) -> list[Finding]:
    out = list(findings)
    for f in out:
        if not f.blocking_class:
            f.status = "informational"
            continue
        match = next((e for e in exemptions if e.matches(f)), None)
        if match:
            f.status, f.exception = "excepted", f"{match.owner} until {match.expires}: {match.reason}"
        else:
            f.status = "blocked"
    out.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line, f.rule_id))
    return out


# ----------------------------------------------------------------------- reports

_CQ_SEVERITY = {"CRITICAL": "blocker", "HIGH": "critical", "MEDIUM": "major", "LOW": "minor", "UNKNOWN": "info"}
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "UNKNOWN": "note"}


def code_quality(findings: list[Finding]) -> list[dict]:
    return [{
        "description": f"[{f.tool}] {f.rule_id}: {f.title}",
        "check_name": f.rule_id,
        "fingerprint": f.fingerprint,
        "severity": "blocker" if f.kind == "secret" else _CQ_SEVERITY[f.severity],
        "location": {"path": f.path or ".", "lines": {"begin": max(f.line, 1)}},
    } for f in findings if f.status != "excepted"]


def sarif(findings: list[Finding]) -> dict:
    rules, seen = [], set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({"id": f.rule_id, "shortDescription": {"text": f.title}})
    results = []
    for f in findings:
        item = {
            "ruleId": f.rule_id,
            "level": "error" if f.kind == "secret" else _SARIF_LEVEL[f.severity],
            "message": {"text": f.title},
            "partialFingerprints": {"gold/v1": f.fingerprint},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.path or "."},
                "region": {"startLine": max(f.line, 1)}}}],
        }
        if f.status == "excepted":
            item["suppressions"] = [{"kind": "external", "justification": f.exception}]
        results.append(item)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "gold-scan", "rules": rules}}, "results": results}],
    }


def write_reports(out_dir: str, findings: list[Finding], problems: list[str], passed: bool) -> None:
    os.makedirs(out_dir, exist_ok=True)
    counts = {s: sum(1 for f in findings if f.status == s) for s in ("blocked", "excepted", "informational")}
    summary = {"passed": passed, "counts": counts, "problems": problems, "findings": [asdict(f) for f in findings]}
    for name, data in (("gate.json", summary), ("gl-code-quality-report.json", code_quality(findings)), ("results.sarif", sarif(findings))):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")


# -------------------------------------------------------------------------- main


def main(argv: list[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="gate.py", description="Decide whether scanner results pass the gate.")
    ap.add_argument("--trivy", action="append", default=[], metavar="FILE", help="Trivy JSON report (repeatable)")
    ap.add_argument("--checkov", action="append", default=[], metavar="FILE", help="Checkov JSON report (repeatable)")
    ap.add_argument("--exceptions", metavar="FILE", help="exceptions file (default: <path>/.security/exceptions.yaml)")
    ap.add_argument("--path", default=".", help="project root, scanned for inline skips")
    ap.add_argument("--no-skip-scan", action="store_true", help="don't look for inline skips (image scans)")
    ap.add_argument("--out", default=".", help="folder for gate.json, gl-code-quality-report.json and results.sarif")
    ap.add_argument("--today", help="override today's date, YYYY-MM-DD (for tests)")
    ap.add_argument("--max-exception-days", type=int, default=MAX_EXCEPTION_DAYS)
    args = ap.parse_args(argv)

    try:
        if not args.trivy and not args.checkov:
            raise InputError("give at least one --trivy or --checkov report")
        today = _date(args.today) if args.today else datetime.date.today()
        if today is None:
            raise InputError(f"--today must be YYYY-MM-DD (got {args.today!r})")

        findings: list[Finding] = []
        scanner_problems: list[str] = []
        for p in args.trivy:
            findings += parse_trivy(load_json(p), p)
        for p in args.checkov:
            doc = load_json(p)
            findings += parse_checkov(doc, p)
            scanner_problems += checkov_problems(doc, p)

        exceptions_path = args.exceptions or os.path.join(args.path, ".security", "exceptions.yaml")
        exemptions, problems = load_exceptions(exceptions_path, today, args.max_exception_days)
        problems += scanner_problems
        if not args.no_skip_scan:
            problems += find_skips(args.path)
    except InputError as e:
        print(f"gate: {e}", file=sys.stderr)
        return 2

    findings = decide(findings, exemptions)
    blocked = [f for f in findings if f.status == "blocked"]
    passed = not blocked and not problems
    write_reports(args.out, findings, problems, passed)

    for f in blocked:
        where = f"{f.path}:{f.line}" if f.line else f.path
        label = "SECRET " if f.kind == "secret" else "BLOCKED"
        print(f"{label} [{f.severity}] {f.rule_id} {where} {f.resource} - {f.title}".replace("  ", " "), file=out)
    for p in problems:
        print(f"PROBLEM {p}", file=out)
    secrets = sum(1 for f in blocked if f.kind == "secret")
    excepted = sum(1 for f in findings if f.status == "excepted")
    info = sum(1 for f in findings if f.status == "informational")
    print(f"gate: {'passed' if passed else 'FAILED'} - {len(blocked)} blocking ({secrets} secret), "
          f"{excepted} excepted, {info} informational, {len(problems)} problem(s)", file=out)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

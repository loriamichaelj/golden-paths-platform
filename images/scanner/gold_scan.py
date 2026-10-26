#!/usr/bin/env python3
"""gold-scan runs the pinned scanners and hands their reports to gate.py.

  gold-scan static --path DIR --out DIR [--exceptions FILE]
  gold-scan plan   --plan plan.json --out DIR [--path DIR] [--exceptions FILE]
  gold-scan image  --image REF --out DIR [--exceptions FILE]

The scanners only report. gate.py decides, and its exit status is ours:
0 passed, 1 the gate failed, 2 a scanner or input was unusable. A scanner that
crashes fails the run; it is never read as "nothing found".

Environment: GOLD_TRIVY and GOLD_CHECKOV name the scanner programs, and
GOLD_CHECKOV_DIR (default /opt/gold/checkov) holds optional custom checks in
custom/ and a config.yaml.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

import gate


def log(msg: str) -> None:
    print(f"gold-scan: {msg}", file=sys.stderr)


def run(cmd: list[str], stdout_path: str | None = None) -> bool:
    """Run a scanner; True when it ran without error."""
    log(" ".join(cmd) + (f" > {stdout_path}" if stdout_path else ""))
    try:
        if stdout_path:
            with open(stdout_path, "w", encoding="utf-8") as fh:
                rc = subprocess.run(cmd, stdout=fh).returncode
        else:
            rc = subprocess.run(cmd).returncode
    except FileNotFoundError:
        log(f"{cmd[0]} is not installed")
        return False
    if rc != 0:
        log(f"{cmd[0]} exited with status {rc}")
    return rc == 0


def trivy_cmd(sub: str, target: str, out_file: str, scanners: str) -> list[str]:
    return [os.environ.get("GOLD_TRIVY", "trivy"), sub, "--quiet", "--scanners", scanners,
            "--format", "json", "--output", out_file, "--exit-code", "0", target]


def checkov_cmd(source: list[str]) -> list[str]:
    cmd = [os.environ.get("GOLD_CHECKOV", "checkov"), *source, "--quiet", "--soft-fail", "--skip-download", "-o", "json"]
    base = os.environ.get("GOLD_CHECKOV_DIR", "/opt/gold/checkov")
    if os.path.isdir(os.path.join(base, "custom")):
        cmd += ["--external-checks-dir", os.path.join(base, "custom")]
    if os.path.isfile(os.path.join(base, "config.yaml")):
        cmd += ["--config-file", os.path.join(base, "config.yaml")]
    return cmd


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gold-scan", description="Scan, then let gate.py decide.")
    ap.add_argument("mode", choices=["static", "plan", "image"])
    ap.add_argument("--path", default=".", help="project folder (static; exceptions and inline-skip lookup for plan)")
    ap.add_argument("--plan", help="terraform plan JSON (plan mode)")
    ap.add_argument("--image", help="image reference (image mode)")
    ap.add_argument("--out", default=".", help="folder for the reports")
    ap.add_argument("--exceptions", help="exceptions file (default: <path>/.security/exceptions.yaml)")
    args = ap.parse_args(argv)

    if args.mode == "plan" and not args.plan:
        ap.error("plan mode needs --plan")
    if args.mode == "image" and not args.image:
        ap.error("image mode needs --image")
    os.makedirs(args.out, exist_ok=True)
    trivy_out = os.path.join(args.out, "trivy.json")
    checkov_out = os.path.join(args.out, "checkov.json")

    gate_args = ["--out", args.out, "--path", args.path]
    if args.exceptions:
        gate_args += ["--exceptions", args.exceptions]

    ok = True
    if args.mode == "static":
        ok &= run(trivy_cmd("fs", args.path, trivy_out, "secret,vuln,misconfig"))
        ok &= run(checkov_cmd(["-d", args.path]), checkov_out)
        gate_args += ["--trivy", trivy_out, "--checkov", checkov_out]
    elif args.mode == "plan":
        ok &= run(checkov_cmd(["-f", args.plan, "--framework", "terraform_plan"]), checkov_out)
        gate_args += ["--checkov", checkov_out]
    else:
        ok &= run(trivy_cmd("image", args.image, trivy_out, "secret,vuln"))
        gate_args += ["--trivy", trivy_out, "--no-skip-scan"]
    if not ok:
        return 2
    return gate.main(gate_args)


if __name__ == "__main__":
    sys.exit(main())

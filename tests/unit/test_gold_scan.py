"""Tests for images/scanner/gold_scan.py using stand-in scanners.

The stand-ins are small Python programs written to a temp folder at test time.
They copy canned reports and record how they were called.
"""

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "images", "scanner"))

import gold_scan  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")

FAKE_TRIVY = """#!{python}
import json, os, sys
with open(os.environ["FAKE_LOG"], "a") as fh:
    fh.write("trivy " + " ".join(sys.argv[1:]) + "\\n")
mode = os.environ.get("FAKE_TRIVY", "fixture")
if mode == "crash":
    sys.exit(3)
out = sys.argv[sys.argv.index("--output") + 1]
if mode == "garbage":
    open(out, "w").write("not json")
elif mode == "clean":
    json.dump({{"SchemaVersion": 2}}, open(out, "w"))
else:
    open(out, "w").write(open(os.path.join(os.environ["FIXTURES"], "trivy.json")).read())
"""

FAKE_CHECKOV = """#!{python}
import os, sys
with open(os.environ["FAKE_LOG"], "a") as fh:
    fh.write("checkov " + " ".join(sys.argv[1:]) + "\\n")
mode = os.environ.get("FAKE_CHECKOV", "fixture")
if mode == "crash":
    sys.exit(4)
if mode == "clean":
    print('{{"check_type": "terraform", "results": {{"failed_checks": []}}, "summary": {{"failed": 0}}}}')
else:
    print(open(os.path.join(os.environ["FIXTURES"], "checkov.json")).read())
"""


def put(path, text):
    with open(path, "w") as fh:
        fh.write(text)


class GoldScanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.log = os.path.join(self.tmp, "calls.log")
        for name, body in (("fake_trivy", FAKE_TRIVY), ("fake_checkov", FAKE_CHECKOV)):
            path = os.path.join(self.tmp, name)
            with open(path, "w") as fh:
                fh.write(body.format(python=sys.executable))
            os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        self.project = os.path.join(self.tmp, "project")
        os.makedirs(self.project)
        self.out = os.path.join(self.tmp, "out")
        self.env = {
            "GOLD_TRIVY": os.path.join(self.tmp, "fake_trivy"),
            "GOLD_CHECKOV": os.path.join(self.tmp, "fake_checkov"),
            "GOLD_CHECKOV_DIR": os.path.join(self.tmp, "no-such-dir"),
            "FAKE_LOG": self.log,
            "FIXTURES": FIXTURES,
        }

    def scan(self, *args, **extra_env):
        env = {**self.env, **extra_env}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return gold_scan.main(list(args))

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as fh:
            return fh.read().splitlines()

    def test_static_runs_both_scanners_then_the_gate(self):
        code = self.scan("static", "--path", self.project, "--out", self.out)
        self.assertEqual(code, 1)  # the fixtures hold blocking findings
        trivy, checkov = self.calls()
        self.assertIn("fs --quiet --scanners secret,vuln,misconfig --format json", trivy)
        self.assertIn("--exit-code 0", trivy)  # the scanner reports; the gate decides
        self.assertTrue(trivy.endswith(self.project))
        self.assertIn(f"-d {self.project}", checkov)
        for flag in ("--soft-fail", "--skip-download", "-o json"):
            self.assertIn(flag, checkov)
        for name in ("trivy.json", "checkov.json", "gate.json", "results.sarif", "gl-code-quality-report.json"):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)

    def test_clean_scanners_pass(self):
        self.assertEqual(self.scan("static", "--path", self.project, "--out", self.out, FAKE_TRIVY="clean", FAKE_CHECKOV="clean"), 0)

    def test_custom_checks_and_config_are_passed_when_present(self):
        base = os.path.join(self.tmp, "gold")
        os.makedirs(os.path.join(base, "custom"))
        put(os.path.join(base, "config.yaml"), "framework: [terraform]\n")
        self.scan("static", "--path", self.project, "--out", self.out, GOLD_CHECKOV_DIR=base, FAKE_TRIVY="clean", FAKE_CHECKOV="clean")
        checkov = self.calls()[1]
        self.assertIn(f"--external-checks-dir {base}/custom", checkov)
        self.assertIn(f"--config-file {base}/config.yaml", checkov)

    def test_plan_mode_runs_only_checkov_on_the_plan(self):
        plan = os.path.join(self.tmp, "plan.json")
        put(plan, "{}")
        code = self.scan("plan", "--plan", plan, "--path", self.project, "--out", self.out)
        self.assertEqual(code, 1)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        self.assertIn(f"-f {plan} --framework terraform_plan", calls[0])
        self.assertFalse(os.path.exists(os.path.join(self.out, "trivy.json")))

    def test_image_mode_scans_the_image_and_skips_the_source_check(self):
        # A skip comment in the working folder must not matter for an image scan.
        marker = "# check" + "ov:skip=X: y"
        put(os.path.join(self.project, "main.tf"), marker + "\n")
        code = self.scan("image", "--image", "registry.example.com/app:1.0", "--path", self.project, "--out", self.out, FAKE_TRIVY="clean")
        self.assertEqual(code, 0)
        self.assertIn("image --quiet --scanners secret,vuln", self.calls()[0])
        self.assertTrue(self.calls()[0].endswith("registry.example.com/app:1.0"))

    def test_a_crashing_scanner_fails_the_run_without_a_verdict(self):
        for env in ({"FAKE_TRIVY": "crash"}, {"FAKE_CHECKOV": "crash"}):
            with self.subTest(env):
                if os.path.exists(self.out):
                    for f in os.listdir(self.out):
                        os.remove(os.path.join(self.out, f))
                self.assertEqual(self.scan("static", "--path", self.project, "--out", self.out, **env), 2)
                self.assertFalse(os.path.exists(os.path.join(self.out, "gate.json")))

    def test_a_missing_scanner_fails_the_run(self):
        self.assertEqual(self.scan("static", "--path", self.project, "--out", self.out, GOLD_TRIVY="/no/such/trivy"), 2)

    def test_garbage_from_a_scanner_fails_the_run(self):
        self.assertEqual(self.scan("static", "--path", self.project, "--out", self.out, FAKE_TRIVY="garbage"), 2)

    def test_mode_arguments_are_required(self):
        with self.assertRaises(SystemExit):
            self.scan("plan")
        with self.assertRaises(SystemExit):
            self.scan("image")


if __name__ == "__main__":
    unittest.main()

"""Tests for images/scanner/gate.py. Run: python3 -m unittest discover -s tests/unit"""

import datetime
import io
import json
import os
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "images", "scanner"))

import gate  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
TRIVY = os.path.join(FIXTURES, "trivy.json")
CHECKOV = os.path.join(FIXTURES, "checkov.json")
TODAY = "2026-10-26"
# Built from pieces so this file never contains the literal inline-skip text.
SKIP_COMMENT = "# check" + "ov:skip=CKV_AWS_18: because"
IGNORE_COMMENT = "#tri" + "vy:ignore:AVD-AWS-0086"


def run_gate(*args):
    out = io.StringIO()
    code = gate.main(list(args), out=out)
    return code, out.getvalue()


def trivy_doc(*vulns):
    """A Trivy report holding only the given (id, severity) vulnerabilities."""
    return {"SchemaVersion": 2, "Results": [{"Target": "app/requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": i, "PkgName": "pkg", "InstalledVersion": "1.0", "Severity": s, "Title": "t"} for i, s in vulns]}]}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def write(self, name, content, binary=False):
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content if isinstance(content, str) else json.dumps(content))
        return path

    def clean_project(self):
        root = os.path.join(self.tmp, "project")
        os.makedirs(root)
        return root


class ParseTests(unittest.TestCase):
    def test_trivy_fixture_is_read_by_kind(self):
        with open(TRIVY) as fh:
            findings = gate.parse_trivy(json.load(fh))
        kinds = {}
        for f in findings:
            kinds.setdefault(f.kind, []).append(f)
        self.assertEqual(len(kinds["secret"]), 1)
        self.assertEqual(kinds["secret"][0].severity, "CRITICAL")
        self.assertEqual(len(kinds["vulnerability"]), 5)
        self.assertEqual(len(kinds["misconfig"]), 6)
        self.assertTrue(all(f.tool == "trivy" for f in findings))

    def test_trivy_ignores_passing_misconfigurations(self):
        doc = {"SchemaVersion": 2, "Results": [{"Target": "x.tf", "Misconfigurations": [
            {"ID": "A", "Severity": "HIGH", "Status": "PASS"}, {"ID": "B", "Severity": "HIGH", "Status": "FAIL"}]}]}
        self.assertEqual([f.rule_id for f in gate.parse_trivy(doc)], ["B"])

    def test_checkov_failures_default_to_high(self):
        with open(CHECKOV) as fh:
            findings = gate.parse_checkov(json.load(fh))
        self.assertEqual(len(findings), 5)
        self.assertTrue(all(f.severity == "HIGH" and f.kind == "policy" for f in findings))
        self.assertFalse(findings[0].path.startswith("/"))

    def test_checkov_accepts_one_report_per_framework(self):
        with open(CHECKOV) as fh:
            one = json.load(fh)
        self.assertEqual(len(gate.parse_checkov([one, one])), 10)

    def test_unrecognised_documents_are_rejected(self):
        with self.assertRaises(gate.InputError):
            gate.parse_trivy({"hello": "world"})
        with self.assertRaises(gate.InputError):
            gate.parse_checkov({"hello": "world"})
        with self.assertRaises(gate.InputError):
            gate.parse_checkov([1])

    def test_checkov_with_nothing_to_scan_prints_a_bare_summary(self):
        bare = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0, "resource_count": 0, "checkov_version": "3.3.27"}
        self.assertEqual(gate.parse_checkov(bare), [])
        self.assertEqual(gate.checkov_problems(bare), [])

    def test_files_checkov_could_not_parse_are_problems(self):
        full = {"check_type": "terraform", "results": {"failed_checks": [], "parsing_errors": ["/infra/broken.tf"]}, "summary": {}}
        self.assertEqual(gate.checkov_problems(full, "c.json"), ["c.json: checkov could not parse /infra/broken.tf"])
        bare = {"passed": 0, "failed": 0, "parsing_errors": 2, "checkov_version": "3.3.27"}
        self.assertEqual(gate.checkov_problems(bare, "c.json"), ["c.json: checkov could not parse 2 file(s)"])

    def test_a_report_with_nothing_found_is_fine(self):
        self.assertEqual(gate.parse_trivy({"SchemaVersion": 2}), [])
        self.assertEqual(gate.parse_checkov({"summary": {"failed": 0}}), [])


class DecideTests(unittest.TestCase):
    def finding(self, rule, severity, kind="vulnerability", path="a", resource="r"):
        return gate.Finding("trivy", rule, severity, "title", path, 1, resource, kind)

    def exemption(self, check, **kw):
        return gate.Exemption(check, "reason", "team-a", datetime.date(2027, 1, 1), kw.get("resource", ""), kw.get("path", ""))

    def test_high_and_critical_and_secrets_block(self):
        out = gate.decide([self.finding("A", "HIGH"), self.finding("B", "CRITICAL"), self.finding("C", "LOW", "secret")], [])
        self.assertEqual({f.rule_id: f.status for f in out}, {"A": "blocked", "B": "blocked", "C": "blocked"})

    def test_medium_low_and_unknown_only_inform(self):
        out = gate.decide([self.finding("A", "MEDIUM"), self.finding("B", "LOW"), self.finding("C", "UNKNOWN")], [])
        self.assertTrue(all(f.status == "informational" for f in out))

    def test_an_exception_excepts_only_what_it_matches(self):
        findings = [self.finding("A", "HIGH", resource="aws_s3_bucket.logs"), self.finding("A", "HIGH", resource="aws_s3_bucket.data"), self.finding("B", "HIGH")]
        out = gate.decide(findings, [self.exemption("A", resource="aws_s3_bucket.logs")])
        got = {(f.rule_id, f.resource): f.status for f in out}
        self.assertEqual(got[("A", "aws_s3_bucket.logs")], "excepted")
        self.assertEqual(got[("A", "aws_s3_bucket.data")], "blocked")
        self.assertEqual(got[("B", "r")], "blocked")

    def test_path_globs(self):
        out = gate.decide([self.finding("A", "HIGH", path="infra/main.tf"), self.finding("A", "HIGH", path="other/main.tf")], [self.exemption("A", path="infra/*")])
        self.assertEqual(sorted(f.status for f in out), ["blocked", "excepted"])

    def test_findings_sorted_worst_first(self):
        out = gate.decide([self.finding("L", "LOW"), self.finding("C", "CRITICAL"), self.finding("H", "HIGH")], [])
        self.assertEqual([f.rule_id for f in out], ["C", "H", "L"])


class ExceptionFileTests(Base):
    def load(self, text):
        path = self.write(".security/exceptions.yaml", textwrap.dedent(text))
        return gate.load_exceptions(path, datetime.date(2026, 10, 26), 180)

    def test_a_complete_entry_is_usable(self):
        usable, problems = self.load("""
            exceptions:
              - check: CKV_AWS_18
                resource: aws_s3_bucket.logs
                reason: Access logs for the log bucket would loop
                owner: team-a
                expires: 2027-03-01
        """)
        self.assertEqual(problems, [])
        self.assertEqual((usable[0].check, usable[0].owner, usable[0].expires), ("CKV_AWS_18", "team-a", datetime.date(2027, 3, 1)))

    def test_missing_fields_are_problems(self):
        usable, problems = self.load("exceptions:\n  - check: A\n    reason: why\n    expires: 2027-01-01\n")
        self.assertEqual(usable, [])
        self.assertIn("missing owner", problems[0])

    def test_expired_and_too_far_out_and_bad_dates(self):
        usable, problems = self.load("""
            exceptions:
              - {check: A, reason: r, owner: o, expires: 2026-10-25}
              - {check: B, reason: r, owner: o, expires: 2027-04-25}
              - {check: C, reason: r, owner: o, expires: soon}
              - {check: D, reason: r, owner: o, expires: 2027-04-24}
        """)
        self.assertEqual([e.check for e in usable], ["D"])  # exactly 180 days out is allowed
        text = "\n".join(problems)
        self.assertIn("(A) expired on 2026-10-25", text)
        self.assertIn("(B) expires 2027-04-25, more than 180 days out", text)
        self.assertIn("(C) has an expiry that is not a date", text)

    def test_empty_file_and_absent_file(self):
        self.assertEqual(self.load(""), ([], []))
        self.assertEqual(gate.load_exceptions(os.path.join(self.tmp, "nope.yaml"), datetime.date.today(), 180), ([], []))
        self.assertEqual(gate.load_exceptions(None, datetime.date.today(), 180), ([], []))

    def test_wrong_shape_stops_the_gate(self):
        path = self.write("e.yaml", "exceptions: nope\n")
        with self.assertRaises(gate.InputError):
            gate.load_exceptions(path, datetime.date.today(), 180)
        path = self.write("e2.yaml", "exceptions: [1]\n")
        _, problems = gate.load_exceptions(path, datetime.date.today(), 180)
        self.assertIn("must be a mapping", problems[0])


class InlineSkipTests(Base):
    def test_inline_skips_and_ignore_files_are_found(self):
        root = self.clean_project()
        self.write("project/infra/main.tf", f'resource "x" "y" {{\n  {SKIP_COMMENT}\n}}\n')
        self.write("project/.trivyignore", IGNORE_COMMENT + "\n")
        self.write("project/.checkov.yaml", "skip-check:\n  - CKV_AWS_18\n")
        problems = "\n".join(gate.find_skips(root))
        self.assertIn("infra/main.tf:2: inline skips are not allowed", problems)
        self.assertIn(".trivyignore: ignore files are not allowed", problems)
        self.assertIn(".checkov.yaml: skip-check is not allowed", problems)

    def test_prose_that_only_mentions_the_syntax_is_not_flagged(self):
        root = self.clean_project()
        self.write("project/notes.md", "Inline " + "check" + "ov:skip comments and " + "tri" + "vy:ignore are not allowed.\n")
        self.assertEqual(gate.find_skips(root), [])

    def test_quiet_when_there_are_none(self):
        root = self.clean_project()
        self.write("project/main.tf", 'resource "x" "y" {}\n')
        self.assertEqual(gate.find_skips(root), [])

    def test_vendored_and_security_folders_are_not_scanned(self):
        root = self.clean_project()
        for d in (".git", ".terraform", "node_modules", ".security"):
            self.write(f"project/{d}/file.txt", SKIP_COMMENT + "\n")
        self.assertEqual(gate.find_skips(root), [])


class MainTests(Base):
    def test_fixtures_fail_the_gate_and_write_reports(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        code, text = run_gate("--trivy", TRIVY, "--checkov", CHECKOV, "--path", root, "--out", out, "--today", TODAY)
        self.assertEqual(code, 1)
        self.assertIn("SECRET", text)
        self.assertIn("gate: FAILED - ", text)
        with open(os.path.join(out, "gate.json")) as fh:
            summary = json.load(fh)
        self.assertFalse(summary["passed"])
        self.assertEqual(summary["counts"]["blocked"], 1 + 2 + 4 + 5)  # secret + HIGH vulns + HIGH misconfigs + checkov
        with open(os.path.join(out, "results.sarif")) as fh:
            sarif = json.load(fh)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), len(summary["findings"]))
        self.assertTrue(all("partialFingerprints" in r for r in sarif["runs"][0]["results"]))
        with open(os.path.join(out, "gl-code-quality-report.json")) as fh:
            cq = json.load(fh)
        self.assertEqual({c["severity"] for c in cq} <= {"blocker", "critical", "major", "minor", "info"}, True)
        self.assertEqual(len({c["fingerprint"] for c in cq}), len(cq))
        self.assertEqual(sum(1 for c in cq if c["severity"] == "blocker"), 1)  # the secret

    def test_only_low_findings_pass(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        report = self.write("t.json", trivy_doc(("CVE-1", "LOW"), ("CVE-2", "MEDIUM")))
        code, text = run_gate("--trivy", report, "--path", root, "--out", out, "--today", TODAY)
        self.assertEqual(code, 0)
        self.assertIn("gate: passed - 0 blocking (0 secret), 0 excepted, 2 informational, 0 problem(s)", text)

    def test_a_valid_exception_lets_a_high_finding_through(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        report = self.write("t.json", trivy_doc(("CVE-9", "HIGH")))
        self.write("project/.security/exceptions.yaml", "exceptions:\n  - {check: CVE-9, reason: no fix yet, owner: team-a, expires: 2026-12-01}\n")
        code, _ = run_gate("--trivy", report, "--path", root, "--out", out, "--today", TODAY)
        self.assertEqual(code, 0)
        with open(os.path.join(out, "results.sarif")) as fh:
            result = json.load(fh)["runs"][0]["results"][0]
        self.assertEqual(result["suppressions"][0]["kind"], "external")
        self.assertIn("team-a until 2026-12-01", result["suppressions"][0]["justification"])
        with open(os.path.join(out, "gl-code-quality-report.json")) as fh:
            self.assertEqual(json.load(fh), [])  # an excepted finding is not shown as a problem

    def test_an_expired_exception_blocks_again_and_is_reported(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        report = self.write("t.json", trivy_doc(("CVE-9", "HIGH")))
        self.write("project/.security/exceptions.yaml", "exceptions:\n  - {check: CVE-9, reason: r, owner: team-a, expires: 2026-10-01}\n")
        code, text = run_gate("--trivy", report, "--path", root, "--out", out, "--today", TODAY)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED [HIGH] CVE-9", text)
        self.assertIn("PROBLEM", text)
        self.assertIn("expired on 2026-10-01", text)

    def test_exceptions_file_can_be_named_explicitly(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        report = self.write("t.json", trivy_doc(("CVE-9", "HIGH")))
        exc = self.write("elsewhere.yaml", "exceptions:\n  - {check: CVE-9, reason: r, owner: o, expires: 2026-12-01}\n")
        self.assertEqual(run_gate("--trivy", report, "--path", root, "--out", out, "--exceptions", exc, "--today", TODAY)[0], 0)

    def test_an_inline_skip_fails_a_clean_scan(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        self.write("project/main.tf", SKIP_COMMENT + "\n")
        report = self.write("t.json", trivy_doc())
        code, text = run_gate("--trivy", report, "--path", root, "--out", out, "--today", TODAY)
        self.assertEqual(code, 1)
        self.assertIn("inline skips are not allowed", text)
        # image scans have no source tree, so they skip that check
        self.assertEqual(run_gate("--trivy", report, "--path", root, "--out", out, "--no-skip-scan", "--today", TODAY)[0], 0)

    def test_unparsed_files_fail_the_gate(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        report = self.write("c.json", {"check_type": "terraform", "results": {"failed_checks": [], "parsing_errors": ["/infra/broken.tf"]}, "summary": {}})
        code, text = run_gate("--checkov", report, "--path", root, "--out", out, "--today", TODAY)
        self.assertEqual(code, 1)
        self.assertIn("could not parse /infra/broken.tf", text)

    def test_unusable_inputs_exit_2_and_never_pass(self):
        root, out = self.clean_project(), os.path.join(self.tmp, "out")
        empty = self.write("empty.json", "")
        broken = self.write("broken.json", "{nope")
        wrong = self.write("wrong.json", {"hello": "world"})
        good = self.write("good.json", trivy_doc())
        for label, args in {
            "no inputs": [],
            "missing file": ["--trivy", os.path.join(self.tmp, "missing.json")],
            "empty file": ["--trivy", empty],
            "invalid json": ["--trivy", broken],
            "not a trivy report": ["--trivy", wrong],
            "not a checkov report": ["--checkov", wrong],
            "bad date": ["--trivy", good, "--today", "yesterday"],
        }.items():
            with self.subTest(label):
                code, _ = run_gate(*args, "--path", root, "--out", out)
                self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(os.path.join(out, "gate.json")), "no report may be written when the gate cannot decide")


if __name__ == "__main__":
    unittest.main()

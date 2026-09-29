#!/usr/bin/env python3
"""Tests of the release severity policy's exceptions (vuln_policy.py).

    python3 -m unittest discover -s scripts/release -p 'test_vuln_policy.py'

scan.sh runs them before applying the policy, so a gate whose exception
rules have regressed does not run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

POLICY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_policy.py")
TODAY = "2026-09-28"

EXACT = """
[[exception]]
id = "CVE-2025-32434"
package = "torch"
version = ["2.3.1", "2.3.1+cpu"]
severity = "critical"
status = "not_affected"
justification = "vulnerable_code_not_in_execute_path"
reason = "torch.load is never called."
compensating_controls = ["pickled weights are refused at import"]
tracking = "https://github.com/advisories/GHSA-53q9-r3pm-6pq6"
added = 2026-09-27
expires = 2026-12-31
"""


def trivy(pkg="torch", version="2.3.1+cpu", vid="CVE-2025-32434", severity="CRITICAL"):
    return {"ArtifactName": "encompute-training:test", "Results": [{
        "Target": "Python", "Class": "lang-pkgs", "Vulnerabilities": [{
            "VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": version,
            "Severity": severity, "FixedVersion": "2.6.0", "Title": "t"}]}]}


def run(exceptions: str, report: dict | None = None, approval: str = 'approved_on = "2026-09-27"'):
    with tempfile.TemporaryDirectory() as d:
        exc = os.path.join(d, "exceptions.toml")
        with open(exc, "w") as f:
            f.write(f'[approval]\napproved_by = "release-manager"\n{approval}\n' + exceptions)
        args = [sys.executable, POLICY, "--exceptions", exc, "--offline", "--today", TODAY]
        if report is not None:
            rp = os.path.join(d, "trivy.json")
            with open(rp, "w") as f:
                json.dump(report, f)
            args += ["--trivy", rp]
        p = subprocess.run(args, capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr


def without(field: str) -> str:
    return "\n".join(line for line in EXACT.splitlines() if not line.startswith(f"{field} ="))


class ExceptionPolicy(unittest.TestCase):
    def test_an_exact_entry_excepts_its_finding(self):
        code, out = run(EXACT, trivy())
        self.assertEqual(code, 0, out)
        self.assertIn("EXCEPTED (not_affected", out)

    def test_another_version_is_not_matched(self):
        # An analysis of torch 2.3.1 says nothing about 2.3.2.
        code, out = run(EXACT, trivy(version="2.3.2"))
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKING (the exception is for version 2.3.1, 2.3.1+cpu, installed 2.3.2)", out)
        self.assertIn("STALE", out)

    def test_another_package_is_not_matched(self):
        code, out = run(EXACT, trivy(pkg="torchvision", version="2.3.1"))
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKING", out)
        self.assertNotIn("EXCEPTED", out)

    def test_every_required_field_is_required(self):
        for field in ("id", "package", "version", "status", "reason", "compensating_controls",
                      "added", "expires", "tracking"):
            with self.subTest(field=field):
                code, out = run(without(field), trivy())
                self.assertEqual(code, 1, out)
                self.assertIn(f"missing {field}", out)

    def test_an_invalid_entry_fails_even_when_it_matches_nothing(self):
        code, out = run(without("tracking"), None)
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKING  invalid exception CVE-2025-32434", out)

    def test_an_expired_entry_fails(self):
        code, out = run(EXACT.replace("expires = 2026-12-31", "expires = 2026-09-27"), trivy())
        self.assertEqual(code, 1, out)
        self.assertIn("expired 2026-09-27", out)
        self.assertNotIn("EXCEPTED", out)

    def test_an_entry_longer_than_the_maximum_fails(self):
        code, out = run(EXACT.replace("added = 2026-09-27", "added = 2026-01-01"), trivy())
        self.assertEqual(code, 1, out)
        self.assertIn("more than 183", out)

    def test_blanket_entries_fail(self):
        cases = {
            "an id list": ('id = "CVE-2025-32434"', 'id = ["CVE-2025-32434", "CVE-2026-24747"]'),
            "an empty id list": ('id = "CVE-2025-32434"', "id = []"),
            "a wildcard id": ('id = "CVE-2025-32434"', 'id = "CVE-*"'),
            "a wildcard version": ('version = ["2.3.1", "2.3.1+cpu"]', 'version = "2.3.*"'),
            "a version range": ('version = ["2.3.1", "2.3.1+cpu"]', 'version = ">=2.3"'),
            "an empty version list": ('version = ["2.3.1", "2.3.1+cpu"]', "version = []"),
            "a package list": ('package = "torch"', 'package = ["torch", "torchvision"]'),
        }
        for name, (old, new) in cases.items():
            with self.subTest(name):
                self.assertIn(old, EXACT)
                code, out = run(EXACT.replace(old, new), trivy())
                self.assertEqual(code, 1, out)
                self.assertIn("BLOCKING", out)
                self.assertNotIn("EXCEPTED", out)

    def test_a_tracking_link_must_be_a_url(self):
        code, out = run(EXACT.replace('"https://github.com/advisories/GHSA-53q9-r3pm-6pq6"',
                                      '"see upstream"'), trivy())
        self.assertEqual(code, 1, out)
        self.assertIn("not an https URL", out)

    def test_an_entry_added_after_the_approval_is_pending(self):
        code, out = run(EXACT.replace("added = 2026-09-27", "added = 2026-09-28"), trivy())
        self.assertEqual(code, 1, out)
        self.assertIn("after the approval of 2026-09-27", out)

    def test_an_approval_needs_its_date(self):
        code, out = run(EXACT, trivy(), approval="")
        self.assertEqual(code, 1, out)
        self.assertIn("approved_on is missing", out)

    def test_accepted_risk_cannot_pass_a_high(self):
        entry = textwrap.dedent(EXACT).replace('status = "not_affected"', 'status = "accepted_risk"')
        code, out = run(entry, trivy())
        self.assertEqual(code, 1, out)
        self.assertIn("only a not_affected analysis can pass", out)


if __name__ == "__main__":
    unittest.main()

"""Tests for scripts/render_report.py, cvss4.py and mask_secrets.py. Standard library only.

Run: python3 -m unittest discover -s plugins/nexurity/tests
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, SCRIPTS)

import cvss4  # noqa: E402
import render_report  # noqa: E402
from mask_secrets import mask_text  # noqa: E402


def table_rows(markdown):
    """Yield (line, cell count) for every table line, ignoring escaped pipes."""
    for line in markdown.splitlines():
        if line.startswith("|"):
            cells = re.split(r"(?<!\\)\|", line.strip())[1:-1]
            yield line, len(cells)


class RenderTest(unittest.TestCase):
    def render(self, name):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copy(os.path.join(FIXTURES, name), os.path.join(tmp, name))
        out = render_report.render_folder(tmp)
        with open(out, encoding="utf-8") as fh:
            return fh.read()

    def test_audit_booby_traps_are_text(self):
        md = self.render("findings.json")
        self.assertNotIn("<script>", md)
        outside_code = re.sub(r"(`{3,})[^\n]*\n.*?\n\1", "", md, flags=re.S)
        self.assertNotIn("<img", outside_code)
        self.assertNotIn("](https://evil", md)
        self.assertNotIn("![x]", md)
        self.assertIn("\\<script\\>", md)
        self.assertNotIn("hunter2hunter2", md)
        for block in re.split(r"\n\s*\n", md):
            counts = {n for _, n in table_rows(block)}
            self.assertLessEqual(len(counts), 1, block)
        # the evidence fence is longer than the backticks inside it
        self.assertIn("````php\n```", md)
        # no heading comes from the target's text
        headings = [l for l in outside_code.splitlines() if l.startswith("#")]
        self.assertFalse(any("Fake heading" in h for h in headings))

    def test_audit_computed_values(self):
        md = self.render("findings.json")
        # open: critical (25) + high adjusted (12) = 37 -> 63 (Insufficient); to confirm: 1
        self.assertIn("**Security score: 63 / 100** · Insufficient", md)
        self.assertIn("1 finding(s) to confirm not counted", md)
        self.assertIn("| 1 | 2 | 0 | 0 | 1 |", md)   # critical, high, medium, low, info
        self.assertIn("CVSS 4.0: **9.3**", md)
        self.assertIn("Severity adjusted for business impact from Low to High", md)
        self.assertIn("| V-04 |", md)
        self.assertIn("The target is a local development environment", md)

    def test_audit_toc_anchors_match_headings(self):
        md = self.render("findings.json")
        anchors = re.findall(r"\]\(#([^)]+)\)", md)
        used = set()
        slugs = {render_report.slugify(l.lstrip("#").strip(), used) for l in md.splitlines() if l.startswith("#")}
        for anchor in anchors:
            self.assertIn(anchor, slugs)

    def test_incident_computed_values_and_defang(self):
        md = self.render("incident.json")
        self.assertIn("Compromission confirmée", md)
        self.assertIn("16 j 11 h", md)                      # 02/10 03:14 -> 18/10 14:05
        self.assertIn("02/11/2026 22:30", md)               # awareness + 72 h
        self.assertIn("cdn-payment[.]evil[.]example", md)
        self.assertIn("hxxp://evil[.]example/x\\|y", md)
        self.assertIn("203.0.113.42", md)
        self.assertNotIn("http://evil.example", md)
        timeline = [l for l in md.splitlines() if l.startswith("| 02/10/2026")]
        self.assertTrue(timeline[0].startswith("| 02/10/2026 03:14"))   # sorted
        self.assertIn("3f9a…c21e", md)

    def test_pandoc_render_has_no_target_html(self):
        if not shutil.which("pandoc"):
            self.skipTest("pandoc not installed")
        for name in ("findings.json", "incident.json"):
            md = self.render(name)
            html = subprocess.run(["pandoc", "-f", "gfm", "-t", "html"], input=md, capture_output=True, text=True).stdout
            self.assertNotIn("<script", html)
            self.assertNotIn("<img", html)
            self.assertNotIn('href="http', html.replace('href="#', ''))

    def test_invalid_vector_is_refused(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        with open(os.path.join(FIXTURES, "findings.json")) as fh:
            data = json.load(fh)
        data["findings"][0]["cvss_vector"] = "CVSS:4.0/AV:N/AC:L"
        with open(os.path.join(tmp, "findings.json"), "w") as fh:
            json.dump(data, fh)
        with self.assertRaises(render_report.ReportError):
            render_report.render_folder(tmp)

    def test_stored_score_mismatch_is_refused(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        with open(os.path.join(FIXTURES, "findings.json")) as fh:
            data = json.load(fh)
        data["findings"][0]["cvss_score"] = 7.0
        with open(os.path.join(tmp, "findings.json"), "w") as fh:
            json.dump(data, fh)
        with self.assertRaises(render_report.ReportError):
            render_report.render_folder(tmp)


class Cvss4Test(unittest.TestCase):
    KNOWN = {
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 9.3,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": 10.0,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N": 0.0,
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": 8.5,
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N": 5.3,
        "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N": 1.0,
    }

    def test_known_scores(self):
        for vector, expected in self.KNOWN.items():
            self.assertEqual(cvss4.score(vector), expected, vector)

    def test_severity_thresholds(self):
        self.assertEqual(cvss4.severity(9.0), "critical")
        self.assertEqual(cvss4.severity(8.9), "high")
        self.assertEqual(cvss4.severity(4.0), "medium")
        self.assertEqual(cvss4.severity(0.1), "low")
        self.assertEqual(cvss4.severity(0.0), "none")

    def test_invalid_vectors(self):
        for vector in ("", "CVSS:3.1/AV:N", "CVSS:4.0/AV:N/AC:L", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                       "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                       "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/SA:N"):
            with self.assertRaises(cvss4.InvalidVector, msg=vector):
                cvss4.score(vector)


class MaskTest(unittest.TestCase):
    def test_masks(self):
        self.assertNotIn("hunter2hunter2", mask_text('password = "hunter2hunter2"'))
        self.assertNotIn("a" * 36, mask_text("token ghp_" + "a" * 36))
        masked = mask_text("AKIAABCDEFGHIJKLMNOP")
        self.assertEqual(masked, "AKIA…MNOP")
        self.assertIn("user:", mask_text("https://user:supersecret@host/db"))
        self.assertNotIn("supersecret", mask_text("https://user:supersecret@host/db"))


if __name__ == "__main__":
    unittest.main()

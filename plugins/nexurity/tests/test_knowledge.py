"""Tests for knowledge.py (the ledger of the ten shipped sources) and its section in the report.

Run: python3 -m unittest discover -s plugins/nexurity/tests
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))

import knowledge  # noqa: E402
import render_report  # noqa: E402


def put(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content if isinstance(content, str) else json.dumps(content))


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = os.path.join(self.tmp.name, "site")
        self.folder = os.path.join(self.target, ".nexurity", "AUD-2026-001")
        put(os.path.join(self.target, "index.php"), "<?php echo 1;")

    def tearDown(self):
        self.tmp.cleanup()

    def status(self, result):
        return {row["id"]: (row["status"], row.get("reason") or sorted(row["used_by"])) for row in result["sources"]}

    def test_php_code_audit(self):
        put(os.path.join(self.folder, "audit-config.json"), {"type": "code", "target": self.target})
        put(os.path.join(self.folder, "recon.json"), {"stack": "PHP", "checklists_used": ["CF RECONNAISSANCE.md"]})
        put(os.path.join(self.folder, "candidates-hunter-web.json"), {"candidates": [], "coverage": {"checklists_used": [
            "CF HUNTING.md", "SK auditing-code-for-vulnerabilities/SKILL.md", "NR owasp-top10.md", "VA security-auditor.md"]}})
        put(os.path.join(self.folder, "candidates-hunter-hygiene.json"), {"coverage": {"checklists_used": ["nud3l-gist"]}})
        put(os.path.join(self.folder, "verdicts-1.json"), {"verdicts": [], "coverage": {"checklists_used": ["CCSR findings_filter.py"]}})
        put(os.path.join(self.folder, "tools", "semgrep.json"), "{}")
        result = knowledge.ledger(self.tmp.name, self.folder)
        self.assertEqual([row["id"] for row in result["sources"]], [s["id"] for s in knowledge.SOURCES])
        self.assertEqual(len(result["sources"]), 10)
        self.assertEqual(self.status(result), {
            "cloudflare-security-audit": ("used", ["hunter-web", "recon"]),
            "cloudflare-skills": ("not_applicable", "no_cloudflare"),
            "semgrep": ("used", ["semgrep"]),
            "nud3l-gist": ("used", ["hunter-hygiene"]),
            "solana-auditor": ("not_applicable", "no_solana"),
            "secskills-core": ("used", ["hunter-web"]),
            "voltagent-subagents": ("used", ["hunter-web"]),
            "netresearch-security-audit": ("used", ["hunter-web"]),
            "codeql": ("not_applicable", "no_codeql_language"),
            "claude-code-security-review": ("used", ["verifier"]),
        })

    def test_missing_tool_and_unreported_source_are_not_run(self):
        put(os.path.join(self.target, "app.js"), "x")
        put(os.path.join(self.target, "wrangler.jsonc"), "{}")
        put(os.path.join(self.folder, "audit-config.json"), {"type": "code", "target": self.target})
        with mock.patch.object(knowledge.tools, "find", return_value=None):
            result = knowledge.ledger(self.tmp.name, self.folder)
        rows = self.status(result)
        self.assertEqual(rows["codeql"], ("not_run", "not_installed"))
        self.assertEqual(rows["cloudflare-skills"], ("not_run", "not_reported"))
        self.assertEqual(result["codeql_languages"], ["javascript-typescript"])

    def test_website_audit(self):
        put(os.path.join(self.folder, "audit-config.json"), {"type": "website", "target": "https://example.org"})
        rows = self.status(knowledge.ledger(self.tmp.name, self.folder))
        for source in ("semgrep", "codeql", "solana-auditor", "secskills-core", "nud3l-gist"):
            self.assertEqual(rows[source], ("not_applicable", "no_code"), source)

    def test_report_lists_the_ledger(self):
        os.makedirs(self.folder, exist_ok=True)
        shutil.copy(os.path.join(HERE, "fixtures", "findings.json"), os.path.join(self.folder, "findings.json"))
        put(os.path.join(self.folder, "audit-config.json"), {"type": "code", "target": self.target})
        put(os.path.join(self.folder, "knowledge.json"), knowledge.ledger(self.tmp.name, self.folder))
        out = render_report.render_folder(self.folder)
        with open(out, encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("Methodology sources", md)
        self.assertIn("| cloudflare/skills | Not applicable | no Cloudflare Workers or WAF configuration |", md)
        self.assertEqual(md.count("| github/codeql |"), 1)


if __name__ == "__main__":
    unittest.main()

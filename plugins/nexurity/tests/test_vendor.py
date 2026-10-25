"""Checks on the third-party skills shipped in vendor/ and on the knowledge map that points to them.

Run: python3 -m unittest discover -s plugins/nexurity/tests
"""
import json
import os
import re
import stat
import unittest

PLUGIN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR = os.path.join(PLUGIN, "vendor")
ALLOWED = re.compile(r"(\.md|\.json|\.yaml|\.py|/LICENSE[-A-Za-z0-9.]*)$")


def load_manifest():
    with open(os.path.join(VENDOR, "SOURCES.json"), encoding="utf-8") as fh:
        return json.load(fh)


class VendorTest(unittest.TestCase):
    def test_every_source_has_its_licence_and_a_pinned_commit(self):
        for source in load_manifest()["sources"]:
            self.assertRegex(source["commit"], r"^[0-9a-f]{40}$", source["name"])
            for licence in source["license_files"]:
                self.assertTrue(os.path.isfile(os.path.join(VENDOR, source["dir"], licence)), (source["name"], licence))

    def test_only_reading_material_and_nothing_executable(self):
        dirs = {s["dir"] for s in load_manifest()["sources"]}
        for root, _dirs, files in os.walk(VENDOR):
            for name in files:
                path = os.path.join(root, name)
                rel = os.path.relpath(path, VENDOR).replace(os.sep, "/")
                if rel == "SOURCES.json" or rel == "README.md":
                    continue
                self.assertIn(rel.split("/")[0], dirs, rel)
                self.assertRegex("/" + rel, ALLOWED, rel)
                self.assertFalse(os.stat(path).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), rel)

    def test_offensive_parts_are_not_shipped(self):
        for root, dirs, files in os.walk(VENDOR):
            for name in dirs + files:
                self.assertNotIn("offense", name)
                self.assertNotIn("penetration-tester", name)

    def test_knowledge_map_points_to_existing_files(self):
        with open(os.path.join(PLUGIN, "reference", "KNOWLEDGE.md"), encoding="utf-8") as fh:
            text = fh.read()
        aliases = dict(re.findall(r"^\| (\w+) \| `([^`]+)`", text, re.M))
        self.assertTrue(aliases)
        for alias, names in re.findall(r"\b(%s) ((?:`[^`]+`(?:, | and )?)+)" % "|".join(aliases), text):
            for name in re.findall(r"`([^`]+)`", names):
                if "*" in name:
                    continue
                base = os.path.join(VENDOR, aliases[alias])
                found = any(os.path.exists(os.path.join(base, sub, name)) for sub in ("", "references"))
                self.assertTrue(found, "%s %s" % (alias, name))
        for source in load_manifest()["sources"]:
            self.assertIn(source["dir"] + "/", text, "%s is never used" % source["dir"])


if __name__ == "__main__":
    unittest.main()

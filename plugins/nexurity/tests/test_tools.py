"""Tests for tools.py: finding tools, the first-run marker and the release checks.

The network, Homebrew and installers are replaced: no test installs anything.
Run: python3 -m unittest discover -s plugins/nexurity/tests
"""
import hashlib
import io
import os
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "scripts"))

import tools  # noqa: E402


def tar_with(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


class FindTest(unittest.TestCase):
    def test_nexurity_folder_is_searched_after_path(self):
        with tempfile.TemporaryDirectory() as data, mock.patch("shutil.which", return_value=None), \
                mock.patch.object(tools, "EXTRA_PATHS", []):
            self.assertIsNone(tools.find("gitleaks", data))
            path = os.path.join(data, "bin", "gitleaks")
            tools.write_executable(path, b"#!/bin/sh\n")
            self.assertEqual(tools.find("gitleaks", data), path)
            self.assertEqual(tools.where(data)["gitleaks"], path)


class InstallTest(unittest.TestCase):
    def test_first_run_installs_each_tool_once(self):
        calls = []
        with tempfile.TemporaryDirectory() as data, \
                mock.patch.object(tools, "find", return_value=None), \
                mock.patch.object(tools, "brew_path", return_value=None), \
                mock.patch.object(tools, "install_one", side_effect=lambda t, d, b: calls.append(t) or ("failed", "offline")):
            first = tools.install(data, first_run=True)
            second = tools.install(data, first_run=True)
        self.assertEqual(calls, tools.TOOLS)
        self.assertIn("codeql", calls)
        self.assertIn("skipped", second)
        self.assertEqual(first["attempted"], sorted(tools.TOOLS))

    def test_first_run_after_an_update_installs_only_new_tools(self):
        calls = []
        with tempfile.TemporaryDirectory() as data:
            tools.common.write_json(os.path.join(data, "tools-setup.json"),
                                    {"date": "earlier", "results": [{"tool": t} for t in tools.TOOLS if t != "codeql"]})
            with mock.patch.object(tools, "find", return_value=None), \
                    mock.patch.object(tools, "brew_path", return_value=None), \
                    mock.patch.object(tools, "install_one", side_effect=lambda t, d, b: calls.append(t) or ("failed", "x")):
                tools.install(data, first_run=True)
        self.assertEqual(calls, ["codeql"])

    def test_codeql_bundle_checksum_is_enforced(self):
        with tempfile.TemporaryDirectory() as data, \
                mock.patch.object(tools, "platform_names", return_value=("linux", "x86_64")), \
                mock.patch.object(tools, "run", return_value="x\trefs/tags/codeql-bundle-v2.27.3\n"), \
                mock.patch.object(tools, "http_get", return_value=b"%s  codeql-bundle-linux64.tar.gz" % (b"a" * 64)), \
                mock.patch.object(tools, "download_file", return_value="b" * 64), \
                mock.patch("shutil.disk_usage", return_value=mock.Mock(free=100 << 30)):
            with self.assertRaises(tools.InstallError):
                tools.install_codeql(data)
            self.assertFalse(os.path.exists(os.path.join(data, "tools", "codeql")))

    def test_cargo_audit_needs_rust(self):
        with tempfile.TemporaryDirectory() as home, mock.patch("shutil.which", return_value=None), \
                mock.patch("os.path.expanduser", return_value=home):
            method, reason = tools.install_one("cargo-audit", home, None)
        self.assertEqual(method, "skipped")
        self.assertIn("Rust", reason)

    def test_release_checksum_is_enforced(self):
        archive = tar_with({"gitleaks": b"binary", "README.md": b"x"})
        good = hashlib.sha256(archive).hexdigest()

        def fake_get(url, checksum):
            if url.endswith("checksums.txt"):
                return ("%s  gitleaks_8.30.1_linux_x64.tar.gz\n" % checksum).encode()
            return archive

        with tempfile.TemporaryDirectory() as data, \
                mock.patch.object(tools, "latest_tag", return_value="v8.30.1"), \
                mock.patch.object(tools, "platform_names", return_value=("linux", "x86_64")):
            with mock.patch.object(tools, "http_get", side_effect=lambda u: fake_get(u, good)):
                self.assertEqual(tools.install_release("gitleaks", data), "8.30.1")
                with open(os.path.join(data, "bin", "gitleaks"), "rb") as fh:
                    self.assertEqual(fh.read(), b"binary")
            with mock.patch.object(tools, "http_get", side_effect=lambda u: fake_get(u, "0" * 64)):
                with self.assertRaises(tools.InstallError):
                    tools.install_release("gitleaks", os.path.join(data, "other"))
            self.assertFalse(os.path.exists(os.path.join(data, "other", "bin", "gitleaks")))

    def test_source_archive_cannot_escape(self):
        archive = tar_with({"lynis-master/lynis": b"#!/bin/sh", "lynis-master/../../evil": b"x",
                            "/etc/evil": b"x"})
        with tempfile.TemporaryDirectory() as data, mock.patch("shutil.which", return_value=None), \
                mock.patch.object(tools, "http_get", return_value=archive):
            tools.install_source("lynis", data)
            self.assertTrue(os.access(os.path.join(data, "tools", "lynis", "lynis"), os.X_OK))
            self.assertFalse(os.path.exists(os.path.join(os.path.dirname(data), "evil")))
            self.assertEqual(os.listdir(os.path.join(data, "tools", "lynis")), ["lynis"])


if __name__ == "__main__":
    unittest.main()

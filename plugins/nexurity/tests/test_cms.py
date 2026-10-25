"""Tests for cms.py: detection, comparison with the official files, vulnerabilities and updates.

The network is replaced by fixtures: no test reaches WordPress.org, NVD, OSV or GitHub.
Run: python3 -m unittest discover -s plugins/nexurity/tests
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.parse
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)

import cms  # noqa: E402


def put(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(content.encode() if isinstance(content, str) else content)


def scan(args):
    with contextlib.redirect_stdout(io.StringIO()):
        return cms.main(["scan"] + args)


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


class FakeNetwork:
    """Answers by URL prefix; records every URL asked for."""

    def __init__(self, routes, tags=None):
        self.routes, self.tags, self.calls = routes, tags or {}, []

    def __enter__(self):
        self.saved = (cms.http_get, cms.git_tags, cms.NVD_DELAY)
        cms.http_get = self.get
        cms.git_tags = lambda url: self.tags.get(url, [])
        cms.NVD_DELAY = 0
        return self

    def __exit__(self, *exc):
        cms.http_get, cms.git_tags, cms.NVD_DELAY = self.saved

    def get(self, url, headers=None, data=None, timeout=None):
        self.calls.append(url)
        for prefix, answer in self.routes.items():
            if url.startswith(prefix):
                answer = answer(url) if callable(answer) else answer
                if answer is None:
                    return None
                return answer if isinstance(answer, bytes) else json.dumps(answer).encode()
        return None


WP_LOAD = "<?php\nfunction wp_load() {\n\treturn true;\n}\n"
WP_FILES = {"wp-load.php": WP_LOAD, "wp-includes/version.php": "<?php\n$wp_version = '6.4.3';\n",
            "wp-includes/functions.php": "<?php\n// functions\n", "wp-admin/index.php": "<?php\n// admin\n",
            "wp-content/index.php": "<?php\n// Silence is golden.\n", "readme.html": "<html></html>"}


def wordpress_site(root):
    for rel, content in WP_FILES.items():
        put(root, rel, content)
    put(root, "wp-load.php", WP_LOAD + "@eval($_POST['x']);\n")             # modified core file
    put(root, "wp-includes/class-wp-cache.php", "<?php system($_GET['c']);")  # added in a core folder
    put(root, "wp-content/uploads/2024/01/x.php", "<?php echo 1;")           # code in uploads
    put(root, "wp-content/uploads/2024/01/photo.jpg", b"\xff\xd8")
    put(root, "wp-config.php", "<?php define('DB_NAME', 'x');")
    os.remove(os.path.join(root, "readme.html"))                              # optional, removed
    put(root, "wp-content/plugins/contact-form-7/wp-contact-form-7.php",
        "<?php\n/*\nPlugin Name: Contact Form 7\nVersion: 5.3.1\n*/\n")
    put(root, "wp-content/themes/mytheme/style.css", "/*\nTheme Name: Mine\nVersion: 1.0\n*/")


def wordpress_routes():
    checksums = {"checksums": {rel: md5(content) for rel, content in WP_FILES.items()}}
    nvd_core = {"vulnerabilities": [
        {"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "Core flaw"}],
                 "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                              "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                                                              "versionStartIncluding": "6.4", "versionEndExcluding": "6.4.5"}]}]}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": 6.1}}]}}},
        {"cve": {"id": "CVE-2024-0002", "descriptions": [{"lang": "en", "value": "Fixed long ago"}],
                 "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                              "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                                                              "versionEndExcluding": "6.0"}]}]}]}},
    ]}
    nvd_plugin = {"vulnerabilities": [
        {"cve": {"id": "CVE-2020-35489", "descriptions": [{"lang": "en", "value": "Upload bypass"}],
                 "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                              "criteria": "cpe:2.3:a:rocklobster:contact_form_7:*:*:*:*:*:wordpress:*:*",
                                                              "versionEndExcluding": "5.3.2"}]}]}]}},
        {"cve": {"id": "CVE-2099-0001", "descriptions": [{"lang": "en", "value": "Other plugin on WordPress"}],
                 "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                              "criteria": "cpe:2.3:a:x:other:*:*:*:*:*:wordpress:*:*"},
                                                             {"vulnerable": False,
                                                              "criteria": "cpe:2.3:a:rocklobster:contact_form_7:*:*:*:*:*:wordpress:*:*"}]}]}]}},
    ]}

    def nvd(url):
        url = urllib.parse.unquote(url)
        return nvd_plugin if "contact_form_7" in url else (nvd_core if "wordpress:wordpress" in url else {"vulnerabilities": []})

    def svn(url):
        rel = url.split("/tags/6.4.3/", 1)[1]
        return WP_FILES.get(rel, "").encode() or None

    return {
        "https://api.wordpress.org/core/checksums/": checksums,
        "https://core.svn.wordpress.org/tags/": svn,
        "https://downloads.wordpress.org/plugin-checksums/": None,
        "https://services.nvd.nist.gov/": nvd,
        "https://api.osv.dev/": {"vulns": []},
        "https://api.wordpress.org/core/version-check/": {"offers": [{"current": "6.6.2"}, {"current": "6.4.5"}]},
        "https://api.wordpress.org/core/stable-check/": {"6.4.3": "insecure"},
        "https://api.wordpress.org/plugins/info/": {"version": "5.9.8"},
        "https://api.wordpress.org/themes/info/": {"error": "Theme not found"},
    }


class VersionTest(unittest.TestCase):
    def test_parse_and_compare(self):
        self.assertEqual(cms.parse_version("8.x-1.5"), ("8.x", (1, 5)))
        self.assertEqual(cms.parse_version("2.4.7-p3"), ("", (2, 4, 7, 3)))
        self.assertIsNone(cms.parse_version("9.0.0-beta.1"))
        self.assertTrue(cms.is_newer("1.7.8.11", "1.7.8.9"))
        self.assertFalse(cms.is_newer("8.x-1.5", "2.0.0"))
        self.assertEqual(cms.latest_of(["6.4.5", "6.6.2", "6.5.1"], "6.4.3", branch=True), "6.4.5")
        self.assertEqual(cms.latest_of(["6.4.5", "6.6.2", "13.1"], "6.4.3"), "13.1")
        self.assertEqual(cms.tag_versions(["5.1.2", "13.1", "5.2.0-rc1", "v5.1.4"], cms.TAG_FORMAT["joomla"]),
                         ["5.1.2", "5.1.4"])

    def test_fixed_for_installed_prefers_branch(self):
        item = {"fixed_in": ["6.3.5", "6.4.5", "6.6.1"]}
        self.assertEqual(cms.fixed_for(item, "6.4.3"), "6.4.5")
        self.assertEqual(cms.fixed_for(item, "6.5.0"), "6.6.1")


class DetectTest(unittest.TestCase):
    def test_wordpress(self):
        with tempfile.TemporaryDirectory() as tmp:
            wordpress_site(tmp)
            found = cms.detect(tmp)
        self.assertEqual((found["cms"], found["version"]), ("wordpress", "6.4.3"))
        plugin = next(e for e in found["extensions"] if e["kind"] == "plugin")
        self.assertEqual((plugin["slug"], plugin["version"]), ("contact-form-7", "5.3.1"))

    def test_prestashop_drupal_joomla_in_subfolders(self):
        with tempfile.TemporaryDirectory() as tmp:
            put(tmp, "ps/src/Core/Version.php", "<?php class Version { public const VERSION = '8.1.7'; }")
            put(tmp, "ps/classes/Tools.php", "<?php")
            put(tmp, "ps/modules/ps_x/config.xml", "<module><version><![CDATA[2.1.0]]></version><author>PrestaShop</author></module>")
            put(tmp, "dr/web/core/lib/Drupal.php", "<?php class Drupal { const VERSION = '10.2.3'; }")
            put(tmp, "dr/web/modules/contrib/token/token.info.yml", "name: Token\nversion: '8.x-1.10'\nproject: 'token'\n")
            put(tmp, "jo/libraries/src/Version.php",
                "<?php final class Version { public const MAJOR_VERSION = 5; public const MINOR_VERSION = 1; public const PATCH_VERSION = 2; }")
            os.makedirs(os.path.join(tmp, "jo", "administrator"))
            ps, dr, jo = (cms.detect(os.path.join(tmp, d)) for d in ("ps", "dr", "jo"))
        self.assertEqual((ps["cms"], ps["version"], ps["extensions"][0]["version"]), ("prestashop", "8.1.7", "2.1.0"))
        self.assertEqual((dr["cms"], dr["version"]), ("drupal", "10.2.3"))
        self.assertTrue(dr["root"].endswith(os.path.join("dr", "web")))
        self.assertEqual(dr["extensions"][0]["slug"], "token")
        self.assertEqual((jo["cms"], jo["version"]), ("joomla", "5.1.2"))

    def test_untrusted_values_are_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            put(tmp, "wp-includes/version.php", "<?php $wp_version = '6.4/../../x?';")
            put(tmp, "wp-content/plugins/ok/ok.php", "<?php /* Plugin Name: Ok\nVersion: 1.0 & rm */")
            found = cms.detect(tmp)
        self.assertIsNone(found["version"])
        self.assertIsNone(found["extensions"][0]["version"])

    def test_not_a_cms(self):
        with tempfile.TemporaryDirectory() as tmp:
            put(tmp, "index.php", "<?php echo 1;")
            self.assertIsNone(cms.detect(tmp))


class WordPressScanTest(unittest.TestCase):
    def test_integrity_vulnerabilities_updates(self):
        with tempfile.TemporaryDirectory() as tmp, FakeNetwork(wordpress_routes()) as net:
            site, out = os.path.join(tmp, "site"), os.path.join(tmp, "out")
            wordpress_site(site)
            code = scan([site, "--data", os.path.join(tmp, "data"), "--out", out, "--budget", "60"])
            self.assertEqual(code, 0)
            with open(os.path.join(out, "cms.json")) as fh:
                report = json.load(fh)
            with open(os.path.join(out, "diffs", "wp-load.php.diff")) as fh:
                diff = fh.read()
        integ = report["integrity"]
        self.assertEqual([m["path"] for m in integ["modified"]], ["wp-load.php"])
        self.assertIn("+@eval($_POST['x']);", diff)
        self.assertEqual(integ["added"], [{"path": "wp-includes/class-wp-cache.php", "code": True}])
        self.assertEqual([c["path"] for c in integ["code_in_upload_dirs"]], ["wp-content/uploads/2024/01/x.php"])
        self.assertEqual(integ["missing"], [])                        # readme.html is optional
        core = report["vulnerabilities"]["core"]["vulnerabilities"]
        self.assertEqual([(v["id"], v["fixed_for_installed"]) for v in core], [("CVE-2024-0001", "6.4.5")])
        plugin = next(e for e in report["vulnerabilities"]["extensions"] if e["slug"] == "contact-form-7")
        self.assertEqual([v["id"] for v in plugin["vulnerabilities"]], ["CVE-2020-35489"])
        updates = report["updates"]
        self.assertEqual((updates["core"]["latest"], updates["core"]["latest_in_branch"], updates["core"]["status"]),
                         ("6.6.2", "6.4.5", "insecure"))
        self.assertTrue(any(e["component"] == "plugin contact-form-7" and e["update_available"] for e in updates["extensions"]))
        self.assertIn("theme mytheme: not published on wordpress.org", updates["not_checked"])
        self.assertTrue(all("site" not in url for url in net.calls))  # no target path or URL sent

    def test_offline_does_not_touch_the_network(self):
        with tempfile.TemporaryDirectory() as tmp, FakeNetwork({}) as net:
            site = os.path.join(tmp, "site")
            wordpress_site(site)
            scan([site, "--data", os.path.join(tmp, "data"), "--out", os.path.join(tmp, "out"), "--offline"])
        self.assertEqual(net.calls, [])


class PrestaShopArchiveTest(unittest.TestCase):
    def build_release(self, path):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            for rel, content in self.OFFICIAL.items():
                z.writestr(rel, content)
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("prestashop.zip", inner.getvalue())
            z.writestr("index.php", "<?php // installer")

    OFFICIAL = {
        "index.php": "<?php // front",
        "src/Core/Version.php": "<?php class Version { public const VERSION = '8.1.7'; }",
        "classes/Tools.php": "<?php class Tools {}\n",
        "classes/index.php": "<?php // silence",
        "admin/ajax-tab.php": "<?php // admin", "admin/index.php": "<?php // admin index",
        "admin/filemanager/a.php": "<?php // fm",
        "img/index.php": "<?php // silence img", "img/.htaccess": "deny php", "img/logo.jpg": "JPG",
        "install/index.php": "<?php // install",
        "modules/ps_x/config.xml": "<module><version><![CDATA[2.1.0]]></version><author>PrestaShop</author></module>",
        "modules/ps_x/ps_x.php": "<?php class Ps_X {}\n",
        "modules/ps_y/config.xml": "<module><version><![CDATA[1.0.0]]></version><author>PrestaShop</author></module>",
        "modules/ps_y/ps_y.php": "<?php class Ps_Y {}\n",
    }

    def test_nested_release_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, site, out = (os.path.join(tmp, d) for d in ("data", "site", "out"))
            os.makedirs(os.path.join(data, "cms-baselines"))
            self.build_release(os.path.join(data, "cms-baselines", "prestashop-8.1.7.zip"))
            for rel, content in self.OFFICIAL.items():
                if not rel.startswith("install/"):
                    put(site, rel.replace("admin/", "admin4f8k2/"), content)
            put(site, "classes/Tools.php", "<?php class Tools {}\neval($_REQUEST['p']);\n")
            put(site, "classes/Cache.inc.php", "<?php // added")
            put(site, "img/p/1/shell.php", "<?php echo 1;")
            put(site, "img/p/1/index.php", "<?php // silence img")          # PrestaShop copies it: same as official
            put(site, "img/logo.jpg", "MY LOGO")                            # replaced image: not reported
            put(site, "modules/ps_x/ps_x.php", "<?php class Ps_X {}\n// injected\n")
            put(site, "modules/ps_y/config.xml", "<module><version><![CDATA[1.2.0]]></version><author>PrestaShop</author></module>")
            put(site, "modules/ps_y/ps_y.php", "<?php class Ps_Y { /* 1.2.0 */ }\n")
            put(site, "modules/thirdparty/thirdparty.php", "<?php $this->version = '1.0.0';")
            put(site, "app/config/parameters.php", "<?php return [];")
            with FakeNetwork({}):
                scan([site, "--data", data, "--out", out, "--offline"])
            with open(os.path.join(out, "cms.json")) as fh:
                report = json.load(fh)
        integ = report["integrity"]
        self.assertEqual(integ["status"], "ok", integ)
        self.assertEqual(integ["renamed_dirs"], {"admin": "admin4f8k2"})
        self.assertEqual([m["path"] for m in integ["modified"]], ["classes/Tools.php"])
        self.assertTrue(integ["modified"][0]["diff"])
        self.assertEqual([a["path"] for a in integ["added"]], ["classes/Cache.inc.php"])
        self.assertEqual(integ["code_in_upload_dirs"],
                         [{"path": "img/p/1/index.php", "same_as_an_official_file": True},
                          {"path": "img/p/1/shell.php", "same_as_an_official_file": False}])
        self.assertEqual(integ["server_config_in_upload_dirs"], [])     # img/.htaccess is the official one
        self.assertEqual(integ["missing"], [])                           # install/ is optional
        modules = {e["slug"]: e for e in report["extension_integrity"]}
        self.assertEqual([m["path"] for m in modules["ps_x"]["modified"]], ["modules/ps_x/ps_x.php"])
        self.assertEqual(modules["ps_y"]["status"], "not_checked")      # updated since the release
        self.assertEqual(report["vulnerabilities"]["status"], "not_checked")


class SourcesTest(unittest.TestCase):
    def test_nvd_platform_only_match_is_dropped(self):
        item = {"cve": {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:ext:1.0:*:*:*:*:joomla\\!:*:*"},
            {"vulnerable": False, "criteria": "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:*"}]}]}]}}
        self.assertFalse(cms.nvd_affects(item, "joomla\\!", "5.1.2"))
        self.assertTrue(cms.nvd_affects(item, "ext", "1.0"))
        self.assertFalse(cms.nvd_affects(item, "ext", "1.1"))

    def test_drupal_release_history(self):
        xml = (b"<project><project_status>published</project_status><releases>"
               b"<release><version>8.x-1.17</version><status>published</status></release>"
               b"<release><version>8.x-1.14</version><status>published</status><terms><term><name>Release type</name>"
               b"<value>Security update</value></term></terms></release>"
               b"<release><version>8.x-1.x-dev</version><status>published</status></release>"
               b"</releases></project>")
        with FakeNetwork({"https://updates.drupal.org/": xml}):
            entry = cms.drupal_release_history("token", "8.x-1.10", False)
        self.assertEqual((entry["latest"], entry["security_update_available"], entry["security_releases_after_installed"]),
                         ("8.x-1.17", True, ["8.x-1.14"]))

    def test_xml_with_dtd_is_refused(self):
        with FakeNetwork({"https://updates.drupal.org/": b'<!DOCTYPE x [<!ENTITY a "b">]><project/>'}):
            with self.assertRaises(cms.Unavailable):
                cms.drupal_release_history("token", "8.x-1.10", False)

    def test_website_mode_needs_no_files(self):
        with tempfile.TemporaryDirectory() as tmp, FakeNetwork(wordpress_routes()):
            out = os.path.join(tmp, "out")
            scan(["--cms", "wordpress", "--version", "6.4.3", "--data", tmp, "--out", out])
            with open(os.path.join(out, "cms.json")) as fh:
                report = json.load(fh)
        self.assertEqual(report["integrity"]["status"], "not_checked")
        self.assertEqual([v["id"] for v in report["vulnerabilities"]["core"]["vulnerabilities"]], ["CVE-2024-0001"])


if __name__ == "__main__":
    unittest.main()

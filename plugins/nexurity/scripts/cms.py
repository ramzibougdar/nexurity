#!/usr/bin/env python3
"""Detect a CMS, compare its files with the official release, list its known vulnerabilities
and the updates to install.

    cms.py detect PATH
    cms.py scan PATH --data D --out <folder>/tools/cms [--budget 300] [--offline]
    cms.py scan --cms wordpress --version 6.4.3 --data D --out <folder>/tools/cms   (website: no files)

Supported: WordPress, PrestaShop, Drupal, Joomla (detection, integrity, vulnerabilities,
updates) and Magento (detection, vulnerabilities, updates).

- Integrity: WordPress.org checksums for the core and for wordpress.org plugins; the official
  release archive of the same version for PrestaShop, Drupal and Joomla (cached in
  `<data>/cms-baselines/`). Modified files get a unified diff in `<out>/diffs/`.
- Vulnerabilities: NVD (CPE matching on the exact version), OSV.dev (Packagist advisories) and
  WPScan when WPSCAN_API_TOKEN is set. NVD_API_KEY raises the NVD rate limit.
- Updates: WordPress.org API, updates.drupal.org (with security releases), Git tags of the
  official repositories.

Only the CMS name, versions and extension names are sent to these sources, never code, paths
or URLs of the target. The target is only read. Results are leads for `hunter-cms`, not
verdicts. Python standard library only.
"""
import argparse
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

USER_AGENT = "nexurity-cms (+https://github.com/ramzibougdar/nexurity)"
TIMEOUT = 30
MAX_ARCHIVE = 400 << 20
MAX_HASHED = 50 << 20
MAX_DIFF_SOURCE = 1 << 20
MAX_DIFFS = 100
MAX_LIST = 500
KEEP_ARCHIVES = 5
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DELAY = 6.5          # seconds between NVD calls without an API key (5 calls per 30 s)
NVD_DELAY_WITH_KEY = 0.7
SKIP_DIRS = {".git", ".svn", ".hg", ".nexurity", "node_modules", ".idea", ".vscode"}
CODE_EXT = re.compile(r"\.(php\d?|phtml|pht|phps|phar|inc|cgi|pl|py|sh|asp|aspx|jsp|exe)$", re.I)
SERVER_CONFIG = re.compile(r"(^|/)(\.htaccess|\.user\.ini|php\.ini|web\.config)$", re.I)
TEXT_CODE = re.compile(r"(\.(php\d?|phtml|pht|phps|phar|inc|js|mjs)|/\.htaccess|^\.htaccess)$", re.I)
SAFE_VERSION = re.compile(r"^[0-9][0-9A-Za-z.\-]{0,40}$")
SAFE_SLUG = re.compile(r"^[A-Za-z0-9_.-]{1,100}(/[A-Za-z0-9_.-]{1,100})?$")
SEARCH_ROOTS = ("", "web", "docroot", "public", "public_html", "htdocs", "www", "httpdocs")


# --- network ---------------------------------------------------------------------

class Unavailable(Exception):
    """A source could not be reached or did not answer usefully."""


def http_get(url, headers=None, data=None, timeout=TIMEOUT):
    request = urllib.request.Request(url, data=data, headers=dict({"User-Agent": USER_AGENT}, **(headers or {})))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise Unavailable("%s answered HTTP %s" % (urllib.parse.urlsplit(url).netloc, exc.code))
    except (urllib.error.URLError, OSError) as exc:
        raise Unavailable("%s unreachable (%s)" % (urllib.parse.urlsplit(url).netloc, exc))


def http_json(url, headers=None, data=None):
    body = http_get(url, dict({"Accept": "application/json"}, **(headers or {})), data)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError:
        raise Unavailable("%s did not return JSON" % urllib.parse.urlsplit(url).netloc)


def download(url, path):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    tmp = path + ".part"
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response, open(tmp, "wb") as out:
            size = 0
            for chunk in iter(lambda: response.read(1 << 20), b""):
                size += len(chunk)
                if size > MAX_ARCHIVE:
                    raise Unavailable("archive larger than %d MB" % (MAX_ARCHIVE >> 20))
                out.write(chunk)
        os.replace(tmp, path)
    except urllib.error.HTTPError as exc:
        raise Unavailable("%s answered HTTP %s" % (urllib.parse.urlsplit(url).netloc, exc.code))
    except (urllib.error.URLError, OSError) as exc:
        raise Unavailable("%s unreachable (%s)" % (urllib.parse.urlsplit(url).netloc, exc))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def git_tags(url):
    """Release tags of a public Git repository (no API quota)."""
    if not shutil.which("git"):
        raise Unavailable("git is not installed")
    try:
        result = subprocess.run(["git", "ls-remote", "--tags", "--refs", url], capture_output=True, text=True,
                                timeout=TIMEOUT, env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    except subprocess.TimeoutExpired:
        raise Unavailable("git ls-remote timed out")
    if result.returncode != 0:
        raise Unavailable("git ls-remote failed: %s" % result.stderr.strip()[:200])
    return [line.split("refs/tags/", 1)[1] for line in result.stdout.splitlines() if "refs/tags/" in line]


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def left(self):
        return self.deadline - time.monotonic()

    def check(self, what):
        if self.left() <= 0:
            raise Unavailable("time budget exhausted before %s" % what)


# --- versions ----------------------------------------------------------------------

def parse_version(value):
    """('8.x', (1, 5)) for Drupal-style versions, ('', (6, 4, 3)) otherwise; None if not a release."""
    value = str(value or "").strip().lstrip("vV")
    prefix = ""
    m = re.match(r"^(\d+\.x)-(.+)$", value)
    if m:
        prefix, value = m.group(1), m.group(2)
    m = re.match(r"^(\d+(?:\.\d+)*)(?:-p(\d+))?$", value)
    if not m:
        return None
    numbers = tuple(int(n) for n in m.group(1).split("."))
    return prefix, numbers + ((int(m.group(2)),) if m.group(2) else ())


def is_newer(candidate, installed):
    a, b = parse_version(candidate), parse_version(installed)
    if not a or not b or a[0] != b[0]:
        return False
    return a[1] > b[1]


def same_branch(candidate, installed):
    a, b = parse_version(candidate), parse_version(installed)
    if not a or not b or a[0] != b[0]:
        return False
    depth = max(1, len(b[1]) - 1)
    return a[1][:depth] == b[1][:depth]


def latest_of(versions, installed=None, branch=False):
    best = None
    for v in versions:
        p = parse_version(v)
        if not p:
            continue
        if installed is not None:
            ip = parse_version(installed)
            if not ip or p[0] != ip[0] or (branch and not same_branch(v, installed)):
                continue
        if best is None or p[1] > parse_version(best)[1]:
            best = v
    return best


# --- the target's files ---------------------------------------------------------------

def read_head(path, size=16384):
    try:
        with open(path, "rb") as fh:
            return fh.read(size).decode("utf-8", errors="replace")
    except OSError:
        return ""


def find_root(path, marker):
    for sub in SEARCH_ROOTS:
        root = os.path.join(path, sub) if sub else path
        if os.path.isfile(os.path.join(root, marker)):
            return os.path.abspath(root)
    return None


def php_const(text, name):
    m = re.search(r"""(?:const\s+%s|define\s*\(\s*['"]%s['"])\s*[=,]\s*['"]?([0-9][0-9A-Za-z.\-]*)['"]?""" % (name, name), text)
    return m.group(1) if m else None


def header_field(text, field):
    m = re.search(r"^[ \t/*#@]*%s\s*:\s*(.+?)\s*$" % re.escape(field), text, re.M | re.I)
    return m.group(1).strip() if m else None


def xml_field(text, tag):
    m = re.search(r"<%s>\s*(?:<!\[CDATA\[)?\s*([^<\]]+?)\s*(?:\]\]>)?\s*</%s>" % (tag, tag), text, re.I)
    return m.group(1).strip() if m else None


def subdirs(path):
    try:
        return sorted(e for e in os.listdir(path) if os.path.isdir(os.path.join(path, e)) and not e.startswith("."))
    except OSError:
        return []


def detect_wordpress(path):
    root = find_root(path, "wp-includes/version.php")
    if not root:
        return None
    text = read_head(os.path.join(root, "wp-includes", "version.php"), 65536)
    m = re.search(r"\$wp_version\s*=\s*'([^']+)'", text)
    locale = re.search(r"\$wp_local_package\s*=\s*'([^']+)'", text)
    exts = []
    plugins = os.path.join(root, "wp-content", "plugins")
    for slug in subdirs(plugins):
        version = name = None
        for entry in sorted(os.listdir(os.path.join(plugins, slug))):
            if entry.endswith(".php"):
                head = read_head(os.path.join(plugins, slug, entry), 8192)
                if header_field(head, "Plugin Name"):
                    name, version = header_field(head, "Plugin Name"), header_field(head, "Version")
                    break
        exts.append({"kind": "plugin", "slug": slug, "name": name, "version": version,
                     "path": "wp-content/plugins/%s" % slug})
    themes = os.path.join(root, "wp-content", "themes")
    for slug in subdirs(themes):
        head = read_head(os.path.join(themes, slug, "style.css"), 8192)
        exts.append({"kind": "theme", "slug": slug, "name": header_field(head, "Theme Name"),
                     "version": header_field(head, "Version"), "path": "wp-content/themes/%s" % slug})
    return {"cms": "wordpress", "version": m.group(1) if m else None, "locale": locale.group(1) if locale else None,
            "root": root, "extensions": exts}


def detect_prestashop(path):
    version, root = None, None
    for marker, const in (("src/Core/Version.php", "VERSION"), ("app/AppKernel.php", "VERSION"),
                          ("config/settings.inc.php", "_PS_VERSION_"),
                          ("config/autoload.php", "_PS_VERSION_")):
        r = find_root(path, marker)
        if r and (os.path.isdir(os.path.join(r, "classes")) or os.path.isfile(os.path.join(r, "init.php"))):
            root = root or r
            version = version or php_const(read_head(os.path.join(r, marker), 65536), const)
    if not root:
        return None
    exts = []
    for kind, base in (("module", "modules"), ("theme", "themes")):
        for slug in subdirs(os.path.join(root, base)):
            folder = os.path.join(root, base, slug)
            if slug.startswith("_"):
                continue
            if kind == "module":
                config = read_head(os.path.join(folder, "config.xml"), 8192)
                main = read_head(os.path.join(folder, slug + ".php"), 65536)
                m = re.search(r"\$this->version\s*=\s*['\"]([^'\"]+)['\"]", main)
                version_ext = xml_field(config, "version") or (m.group(1) if m else None)
                if not config and not main:
                    continue
                exts.append({"kind": kind, "slug": slug, "name": xml_field(config, "displayName") or slug,
                             "version": version_ext, "author": xml_field(config, "author"), "path": "%s/%s" % (base, slug)})
            else:
                head = read_head(os.path.join(folder, "config", "theme.yml"), 8192)
                m = re.search(r"^\s*version:\s*['\"]?([0-9][^'\"\s]*)", head, re.M)
                exts.append({"kind": kind, "slug": slug, "name": slug, "version": m.group(1) if m else None,
                             "path": "%s/%s" % (base, slug)})
    return {"cms": "prestashop", "version": version, "root": root, "extensions": exts}


def detect_drupal(path):
    root = find_root(path, "core/lib/Drupal.php")
    legacy = False
    if root:
        version = php_const(read_head(os.path.join(root, "core", "lib", "Drupal.php"), 65536), "VERSION")
    else:
        root = find_root(path, "includes/bootstrap.inc")
        if not root or not os.path.isdir(os.path.join(root, "modules", "system")):
            return None
        legacy = True
        version = php_const(read_head(os.path.join(root, "includes", "bootstrap.inc"), 65536), "VERSION")
    exts, seen = [], set()
    bases = ["sites/all/modules", "sites/all/themes"] if legacy else ["modules", "themes", "profiles"]
    suffix = ".info" if legacy else ".info.yml"
    for base in bases:
        top = os.path.join(root, base)
        for dirpath, dirnames, files in os.walk(top):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d not in ("tests", "test_modules")]
            if dirpath[len(top):].count(os.sep) > 3:
                dirnames[:] = []
            for name in files:
                if not name.endswith(suffix):
                    continue
                text = read_head(os.path.join(dirpath, name), 8192)
                project = re.search(r"""^project\s*[:=]\s*['"]?([a-z0-9_]+)""", text, re.M)
                ver = re.search(r"""^version\s*[:=]\s*['"]?([0-9][^'"\s]*)""", text, re.M)
                slug = project.group(1) if project else name[:-len(suffix)]
                if slug in seen or slug == "drupal":
                    continue
                seen.add(slug)
                exts.append({"kind": "theme" if "themes" in base else "module", "slug": slug,
                             "version": ver.group(1) if ver else None,
                             "path": os.path.relpath(dirpath, root).replace(os.sep, "/")})
    return {"cms": "drupal", "version": version, "root": root, "legacy": legacy, "extensions": exts}


def detect_joomla(path):
    root = None
    for marker in ("libraries/src/Version.php", "libraries/cms/version/version.php"):
        root = find_root(path, marker)
        if root and os.path.isdir(os.path.join(root, "administrator")):
            text = read_head(os.path.join(root, marker), 65536)
            break
        root = None
    if not root:
        return None
    major = re.search(r"MAJOR_VERSION\s*=\s*(\d+)", text)
    if major:
        minor = re.search(r"MINOR_VERSION\s*=\s*(\d+)", text)
        patch = re.search(r"PATCH_VERSION\s*=\s*(\d+)", text)
        version = "%s.%s.%s" % (major.group(1), minor.group(1) if minor else 0, patch.group(1) if patch else 0)
    else:
        release = re.search(r"RELEASE\s*=\s*'([\d.]+)'", text)
        level = re.search(r"DEV_LEVEL\s*=\s*'(\d+)'", text)
        version = "%s.%s" % (release.group(1), level.group(1)) if release and level else None
    exts = []
    for base, kind in (("administrator/components", "component"), ("modules", "module"), ("templates", "template")):
        for slug in subdirs(os.path.join(root, base)):
            folder = os.path.join(root, base, slug)
            manifest = ""
            for candidate in (slug.replace("com_", "") + ".xml", slug + ".xml", "templateDetails.xml"):
                if os.path.isfile(os.path.join(folder, candidate)):
                    manifest = read_head(os.path.join(folder, candidate), 16384)
                    break
            exts.append({"kind": kind, "slug": slug, "name": xml_field(manifest, "name"),
                         "version": xml_field(manifest, "version"), "author": xml_field(manifest, "author"),
                         "path": "%s/%s" % (base, slug)})
    for group in subdirs(os.path.join(root, "plugins")):
        for slug in subdirs(os.path.join(root, "plugins", group)):
            manifest = read_head(os.path.join(root, "plugins", group, slug, slug + ".xml"), 16384)
            exts.append({"kind": "plugin", "slug": "%s/%s" % (group, slug), "name": xml_field(manifest, "name"),
                         "version": xml_field(manifest, "version"), "author": xml_field(manifest, "author"),
                         "path": "plugins/%s/%s" % (group, slug)})
    return {"cms": "joomla", "version": version, "root": root, "extensions": exts}


def detect_magento(path):
    root = find_root(path, "app/etc/di.xml")
    if not root or not os.path.isdir(os.path.join(root, "app", "code")) and not os.path.isfile(os.path.join(root, "composer.lock")):
        return None
    version = None
    lock = common.read_json(os.path.join(root, "composer.lock"), {}) or {}
    for package in lock.get("packages", []):
        if package.get("name") in ("magento/product-community-edition", "magento/magento2-base", "magento/product-enterprise-edition"):
            version = str(package.get("version", "")).lstrip("v")
            break
    return {"cms": "magento", "version": version, "root": root, "extensions": []}


DETECTORS = (detect_wordpress, detect_prestashop, detect_drupal, detect_joomla, detect_magento)


def sanitize(found):
    """Versions and slugs come from the target: keep only plain values (they go into URLs)."""
    if found.get("version") and not SAFE_VERSION.match(found["version"]):
        found["version_unreadable"], found["version"] = found["version"][:80], None
    if found.get("locale") and not re.match(r"^[a-z]{2,3}(_[A-Z]{2})?(_[a-z]+)?$", found["locale"]):
        found["locale"] = None
    kept = []
    for ext in found.get("extensions", []):
        if not SAFE_SLUG.match(ext["slug"]):
            continue
        if ext.get("version") and not SAFE_VERSION.match(ext["version"]):
            ext["version_unreadable"], ext["version"] = ext["version"][:80], None
        kept.append(ext)
    found["extensions"] = kept
    return found


def detect(path):
    path = os.path.abspath(os.path.expanduser(path))
    for detector in DETECTORS:
        found = detector(path)
        if found:
            return sanitize(found)
    return None


# --- per-CMS rules -----------------------------------------------------------------

RULES = {
    "wordpress": {
        "content": ["wp-content/uploads", "wp-content/cache", "wp-content/upgrade", "wp-content/languages"],
        "upload": ["wp-content/uploads"],
        "scope": None,
        "bundled": [("wp-content/plugins", None), ("wp-content/themes", "style.css")],
        "variable": [r"^wp-config\.php$", r"^\.htaccess$", r"^robots\.txt$", r"^\.user\.ini$", r"^php\.ini$",
                     r"^favicon\.ico$", r"^sitemap.*\.xml$", r"^google[0-9a-f]+\.html$", r"^\.well-known/",
                     r"^wp-content/(advanced-cache|object-cache|db|db-error|maintenance|sunrise|fatal-error-handler)\.php$",
                     r"^wp-content/debug\.log$", r"^wp-content/index\.php$"],
        "optional": [r"^readme\.html$", r"^license\.txt$", r"^wp-config-sample\.php$", r"^wp-content/",
                     r"^xmlrpc\.php$"],
        "expected_modified": [],
    },
    "prestashop": {
        "content": ["img", "upload", "download", "var", "cache", "translations", "mails", "override", "app/config",
                    "config/xml", "config/themes", "log"],
        "upload": ["img", "upload", "download"],
        "scope": None,
        "bundled": [("modules", "config.xml"), ("themes", "config/theme.yml")],
        "variable": [r"^\.htaccess$", r"^robots\.txt$", r"^config/settings\.inc\.php$", r"^app/config/parameters\.(php|yml)$",
                     r"^\.user\.ini$", r"^php\.ini$", r"^favicon\.ico$", r"^sitemap.*\.xml$", r"^google[0-9a-f]+\.html$",
                     r"^\.well-known/", r"(^|/)index\.php$"],
        "optional": [r"^install(-dev)?/", r"^docs/", r"^Install_PrestaShop\.html$", r"\.md$", r"^LICENSES?(\.txt)?$",
                     r"^modules/", r"^themes/", r"^img/", r"^\.github/", r"^tests/"],
        "expected_modified": [r"^\.htaccess$", r"^robots\.txt$", r"^config/defines\.inc\.php$"],
    },
    "drupal": {
        "content": ["sites", "modules", "themes", "profiles/contrib", "profiles/custom", "libraries", "vendor"],
        "upload": ["sites/default/files"],
        "scope": [r"^core/", r"^index\.php$", r"^update\.php$"],
        "variable": [],
        "optional": [r"^core/[A-Z_]+\.txt$", r"^core/(tests|scripts|assets/vendor)/"],
        "expected_modified": [],
    },
    "drupal7": {
        "content": ["sites"],
        "upload": ["sites/default/files"],
        "scope": None,
        "variable": [r"^\.htaccess$", r"^robots\.txt$", r"^web\.config$", r"^\.well-known/", r"^favicon\.ico$"],
        "optional": [r"^[A-Z_]+\.txt$", r"^profiles/testing/", r"^scripts/", r"^install\.php$"],
        "expected_modified": [r"^\.htaccess$", r"^robots\.txt$"],
    },
    "joomla": {
        "content": ["images", "tmp", "cache", "administrator/cache", "logs", "administrator/logs"],
        "upload": ["images", "tmp"],
        "scope": None,
        "variable": [r"^configuration\.php$", r"^\.htaccess$", r"^robots\.txt$", r"^\.user\.ini$", r"^php\.ini$",
                     r"^favicon\.ico$", r"^\.well-known/", r"^sitemap.*\.xml$"],
        "optional": [r"^installation/", r"\.txt$", r"\.md$", r"^htaccess\.txt$", r"^web\.config\.txt$",
                     r"^robots\.txt\.dist$"],
        "expected_modified": [],
    },
}


def rules_for(found):
    if found["cms"] == "drupal" and found.get("legacy"):
        return RULES["drupal7"]
    return RULES.get(found["cms"])


def under(path, dirs):
    return any(path == d or path.startswith(d.rstrip("/") + "/") for d in dirs)


def matches(path, patterns):
    return any(re.search(p, path) for p in patterns)


def walk_tree(root):
    """{relative path: {"sha256", "md5", "size"}} of the target, read-only."""
    files = {}
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in names:
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            files[rel] = full
    return files


def file_hashes(full):
    sha, md5 = hashlib.sha256(), hashlib.md5()
    size = 0
    with open(full, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
            md5.update(chunk)
            size += len(chunk)
            if size > MAX_HASHED:
                return None
    return {"sha256": sha.hexdigest(), "md5": md5.hexdigest()}


class Hasher:
    def __init__(self, files):
        self.files = files
        self.cache = {}

    def get(self, rel):
        if rel not in self.cache:
            try:
                self.cache[rel] = file_hashes(self.files[rel])
            except OSError:
                self.cache[rel] = None
        return self.cache[rel]


# --- official baselines -------------------------------------------------------------

class Baseline:
    """Official files of one release: {path: {"sha256"|"md5": value}} plus a way to read a file."""

    def __init__(self, files, source, reader=None, algo="sha256"):
        self.files = files
        self.source = source
        self.reader = reader
        self.algo = algo
        self.dirs = set()
        for path in files:
            parts = path.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                self.dirs.add("/".join(parts[:i]))

    def read(self, path):
        return self.reader(path) if self.reader else None


def _strip_common_prefix(names):
    tops = {n.split("/", 1)[0] for n in names if "/" in n}
    if len(tops) == 1 and all("/" in n for n in names):
        prefix = tops.pop() + "/"
        return prefix
    return ""


def archive_baseline(path, source):
    """Baseline from a release archive (zip, nested zip for PrestaShop, or tar.gz)."""
    if zipfile.is_zipfile(path):
        archive = zipfile.ZipFile(path)
        names = [n for n in archive.namelist() if not n.endswith("/")]
        inner = [n for n in names if re.match(r"^(prestashop/)?prestashop\.zip$", n)]
        if inner:
            data = archive.read(inner[0])
            archive.close()
            archive = zipfile.ZipFile(io.BytesIO(data))
            names = [n for n in archive.namelist() if not n.endswith("/")]
        prefix = _strip_common_prefix(names)
        members = {n[len(prefix):]: n for n in names if n.startswith(prefix)}
        files = {}
        for rel, name in members.items():
            info = archive.getinfo(name)
            if info.file_size > MAX_HASHED:
                continue
            files[rel] = {"sha256": hashlib.sha256(archive.read(name)).hexdigest()}
        return Baseline(files, source, lambda rel: archive.read(members[rel]) if rel in members else None)
    with tarfile.open(path, "r:*") as archive:
        members = [m for m in archive.getmembers() if m.isfile()]
        prefix = _strip_common_prefix([m.name for m in members])
        files, contents = {}, {}
        for m in members:
            if not m.name.startswith(prefix) or m.size > MAX_HASHED:
                continue
            data = archive.extractfile(m).read()
            rel = m.name[len(prefix):]
            files[rel] = {"sha256": hashlib.sha256(data).hexdigest()}
            if m.size <= MAX_DIFF_SOURCE:
                contents[rel] = data
    return Baseline(files, source, contents.get)


def cached_archive(data, cms, version, url, ext):
    folder = os.path.join(data, "cms-baselines")
    os.makedirs(folder, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", "%s-%s.%s" % (cms, version, ext))
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        download(url, path)
        archives = sorted((os.path.join(folder, n) for n in os.listdir(folder) if not n.endswith(".part")),
                          key=os.path.getmtime, reverse=True)
        for old in archives[KEEP_ARCHIVES:]:
            os.unlink(old)
    else:
        os.utime(path)
    return path


def wordpress_baseline(version, locale, data, offline):
    if offline:
        raise Unavailable("offline mode")
    url = "https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s" % (
        urllib.parse.quote(version), urllib.parse.quote(locale or "en_US"))
    answer = http_json(url)
    checksums = (answer or {}).get("checksums")
    if not checksums and locale and locale != "en_US":
        answer = http_json(url.rsplit("&locale=", 1)[0] + "&locale=en_US")
        checksums = (answer or {}).get("checksums")
    if not isinstance(checksums, dict) or not checksums:
        raise Unavailable("WordPress.org has no checksums for %s" % version)
    files = {p: {"md5": h} for p, h in checksums.items()}

    def reader(rel):
        return http_get("https://core.svn.wordpress.org/tags/%s/%s" % (version, urllib.parse.quote(rel)))
    return Baseline(files, "WordPress.org checksums API, version %s" % version, reader, "md5")


def release_baseline(found, data, offline):
    cms, version = found["cms"], found["version"]
    if cms == "prestashop":
        url = "https://github.com/PrestaShop/PrestaShop/releases/download/%s/prestashop_%s.zip" % (version, version)
        ext = "zip"
    elif cms == "drupal":
        url = "https://ftp.drupal.org/files/projects/drupal-%s.tar.gz" % version
        ext = "tar.gz"
    elif cms == "joomla":
        url = "https://github.com/joomla/joomla-cms/releases/download/%s/Joomla_%s-Stable-Full_Package.zip" % (version, version)
        ext = "zip"
    else:
        raise Unavailable("no official file list for %s (installed with Composer: compare with the lock file)" % cms)
    folder = os.path.join(data, "cms-baselines")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", "%s-%s.%s" % (cms, version, ext))
    if offline and not os.path.exists(os.path.join(folder, name)):
        raise Unavailable("offline mode and no cached release archive")
    path = cached_archive(data, cms, version, url, ext)
    try:
        return archive_baseline(path, "official release archive %s" % url)
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        os.unlink(path)
        raise Unavailable("the release archive could not be read (%s)" % exc)


# --- integrity ------------------------------------------------------------------------

def renamed_dirs(baseline, target_files, rules=None):
    """Top-level folders renamed at install time (PrestaShop's admin folder): best overlap, each used once."""
    base_top = {p.split("/", 1)[0] for p in baseline.files if "/" in p}
    target_top = {p.split("/", 1)[0] for p in target_files if "/" in p}
    pairs = []
    for missing in sorted(base_top - target_top):
        if matches(missing + "/", (rules or {}).get("optional", [])):
            continue
        inside = {p.split("/", 1)[1] for p in baseline.files if p.startswith(missing + "/")}
        for candidate in sorted(target_top - base_top):
            got = {p.split("/", 1)[1] for p in target_files if p.startswith(candidate + "/")}
            shared = len(inside & got)
            if shared >= 2 and shared >= 0.5 * len(inside):
                pairs.append((shared / float(len(inside)), shared, missing, candidate))
    mapping, used = {}, set()
    for _ratio, _shared, missing, candidate in sorted(pairs, reverse=True):
        if missing not in mapping and candidate not in used:
            mapping[missing] = candidate
            used.add(candidate)
    return mapping


def inside_bundled(path, rules):
    """True for files inside an extension folder shipped with the release (compared separately)."""
    for parent, _version_file in rules.get("bundled", []):
        rest = path[len(parent) + 1:] if path.startswith(parent + "/") else None
        if rest and "/" in rest:
            return True
    return False


def compare(baseline, files, rules, hasher, target_prefix=None, baseline_prefix=""):
    """Modified, added and missing files of the target against the official files.

    Whole tree when `target_prefix` is None; otherwise only the target files under `target_prefix`,
    matched with the official files under `baseline_prefix` (an extension folder).
    """
    sub = target_prefix is not None
    mapping = {} if sub else renamed_dirs(baseline, files, rules)
    reverse = {v: k for k, v in mapping.items()}
    scope = None if sub else rules.get("scope")
    official = {h.get(baseline.algo) for h in baseline.files.values()}
    modified, added, missing, upload_code, upload_config = [], [], [], [], []
    seen = set()

    def to_baseline(rel):
        top, _, rest = rel.partition("/")
        return (reverse[top] + "/" + rest) if top in reverse and rest else rel

    for rel in sorted(files):
        if sub:
            if not rel.startswith(target_prefix):
                continue
            base_rel = baseline_prefix + rel[len(target_prefix):]
        else:
            base_rel = to_baseline(rel)
            if scope and not matches(base_rel, scope):
                continue
            if inside_bundled(base_rel, rules):
                continue
        seen.add(base_rel)
        expected = baseline.files.get(base_rel)
        if not sub and under(base_rel, rules.get("upload", [])):
            if CODE_EXT.search(base_rel):
                h = hasher.get(rel) or {}
                if expected is not None and h.get(baseline.algo) == expected.get(baseline.algo):
                    continue
                upload_code.append({"path": rel, "same_as_an_official_file": h.get(baseline.algo) in official})
            elif SERVER_CONFIG.search(base_rel):
                h = hasher.get(rel) or {}
                if expected is None or h.get(baseline.algo) != expected.get(baseline.algo):
                    upload_config.append(rel)
            continue
        in_content = not sub and under(base_rel, rules.get("content", []))
        if expected is not None:
            if in_content and not TEXT_CODE.search(base_rel):
                continue
            h = hasher.get(rel)
            if h is not None and h[baseline.algo] != expected.get(baseline.algo):
                modified.append({"path": rel, "baseline_path": base_rel,
                                 "expected": matches(base_rel, rules.get("expected_modified", []))})
            continue
        if not sub and (in_content or matches(base_rel, rules.get("variable", []))):
            continue
        parent = base_rel.rsplit("/", 1)[0] if "/" in base_rel else ""
        if sub or parent == "" or parent in baseline.dirs:
            added.append({"path": rel, "code": bool(CODE_EXT.search(base_rel))})
    for base_rel in sorted(baseline.files):
        if base_rel in seen:
            continue
        if sub:
            if not base_rel.startswith(baseline_prefix):
                continue
        elif (scope and not matches(base_rel, scope)) or inside_bundled(base_rel, rules) \
                or matches(base_rel, rules.get("optional", [])):
            continue
        missing.append(base_rel)
    result = {"modified": modified, "added": added, "missing": missing}
    if not sub:
        result.update(renamed_dirs=mapping, code_in_upload_dirs=upload_code, server_config_in_upload_dirs=upload_config)
    return result


def write_diff(out, rel, original, current_path, counter):
    if counter[0] >= MAX_DIFFS or original is None:
        return None
    try:
        if os.path.getsize(current_path) > MAX_DIFF_SOURCE or len(original) > MAX_DIFF_SOURCE:
            return None
        with open(current_path, "rb") as fh:
            current = fh.read()
    except OSError:
        return None
    if b"\0" in current[:8192] or b"\0" in original[:8192]:
        return None
    text = "".join(difflib.unified_diff(original.decode("utf-8", "replace").splitlines(True),
                                        current.decode("utf-8", "replace").splitlines(True),
                                        "official/" + rel, "installed/" + rel, n=3))
    if not text:
        return None
    safe = re.sub(r"[^A-Za-z0-9._/-]", "_", rel).replace("..", "_").lstrip("/")
    path = os.path.join(out, "diffs", safe + ".diff")
    if not common.is_within(path, out):
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    counter[0] += 1
    return os.path.relpath(path, out).replace(os.sep, "/")


def add_diffs(result, baseline, files, out, counter, budget):
    for item in result["modified"]:
        item["diff"] = None
        if budget.left() <= 0:
            continue
        try:
            original = baseline.read(item["baseline_path"])
        except Unavailable:
            original = None
        item["diff"] = write_diff(out, item["path"], original, files[item["path"]], counter)


def truncate(result):
    for key in ("modified", "added", "missing", "code_in_upload_dirs", "server_config_in_upload_dirs"):
        if key in result:
            result[key + "_count"] = len(result[key])
            result[key] = result[key][:MAX_LIST]
    return result


def baseline_version(baseline, path, version_file):
    try:
        content = baseline.read("%s/%s" % (path, version_file))
    except Unavailable:
        return None
    text = (content or b"").decode("utf-8", "replace")
    if version_file.endswith(".xml"):
        return xml_field(text, "version")
    if version_file.endswith(".yml"):
        m = re.search(r"^\s*version:\s*['\"]?([0-9][^'\"\s]*)", text, re.M)
        return m.group(1) if m else None
    return header_field(text, "Version")


def bundled_integrity(found, baseline, files, rules, hasher, out, counter, budget):
    """Extensions shipped with the release, compared when the installed version is the shipped one."""
    results = []
    for parent, version_file in rules.get("bundled", []):
        if not version_file:
            continue
        for ext in found["extensions"]:
            if not ext["path"].startswith(parent + "/") or ext["path"] not in baseline.dirs:
                continue
            ext["bundled"] = True
            entry = {"slug": ext["slug"], "kind": ext["kind"], "version": ext.get("version")}
            shipped = baseline_version(baseline, ext["path"], version_file) if budget.left() > 0 else None
            if not shipped or shipped != ext.get("version"):
                entry.update(status="not_checked", shipped_version=shipped,
                             reason="installed version differs from the one shipped with the release; no official "
                                    "file list for it" if shipped else "shipped version unknown")
                results.append(entry)
                continue
            prefix = ext["path"] + "/"
            result = compare(baseline, files, rules, hasher, target_prefix=prefix, baseline_prefix=prefix)
            add_diffs(result, baseline, files, out, counter, budget)
            entry.update(status="ok", baseline="%s (shipped with the release)" % baseline.source, **truncate(result))
            results.append(entry)
    return results


def integrity(found, data, out, offline, budget):
    rules = rules_for(found)
    if not rules:
        return {"status": "not_checked", "reason": "file comparison is not supported for %s" % found["cms"]}, []
    if not found.get("version"):
        return {"status": "not_checked", "reason": "the installed version could not be read"}, []
    try:
        budget.check("the file comparison")
        if found["cms"] == "wordpress":
            baseline = wordpress_baseline(found["version"], found.get("locale"), data, offline)
        else:
            baseline = release_baseline(found, data, offline)
    except Unavailable as exc:
        return {"status": "not_checked", "reason": str(exc)}, []
    files = walk_tree(found["root"])
    hasher = Hasher(files)
    counter = [0]
    result = compare(baseline, files, rules, hasher)
    add_diffs(result, baseline, files, out, counter, budget)
    result.update({"status": "ok", "baseline": baseline.source, "compared_files": len(baseline.files)})
    for ext in found["extensions"]:
        ext["bundled"] = ext["path"] in baseline.dirs
    extensions = bundled_integrity(found, baseline, files, rules, hasher, out, counter, budget)
    if found["cms"] == "wordpress":
        extensions += wordpress_plugins_integrity(found, files, hasher, out, counter, offline, budget)
    return truncate(result), extensions


def wordpress_plugins_integrity(found, files, hasher, out, counter, offline, budget):
    results = []
    for ext in found["extensions"]:
        if ext["kind"] != "plugin":
            continue
        entry = {"slug": ext["slug"], "kind": "plugin", "version": ext.get("version")}
        results.append(entry)
        if offline or not ext.get("version") or budget.left() <= 0:
            entry.update(status="not_checked", reason="offline mode" if offline else
                         ("version not found" if not ext.get("version") else "time budget exhausted"))
            continue
        try:
            answer = http_json("https://downloads.wordpress.org/plugin-checksums/%s/%s.json" % (
                urllib.parse.quote(ext["slug"]), urllib.parse.quote(ext["version"])))
        except Unavailable as exc:
            entry.update(status="not_checked", reason=str(exc))
            continue
        if not answer or not isinstance(answer.get("files"), dict):
            entry.update(status="not_checked", reason="no checksums on wordpress.org (premium or custom plugin, or "
                                                      "unknown version)")
            continue
        baseline_files = {}
        for path, h in answer["files"].items():
            sha = (h or {}).get("sha256")
            baseline_files[path] = {"sha256": sha[0] if isinstance(sha, list) else sha}
        slug, version = ext["slug"], ext["version"]

        def reader(rel, slug=slug, version=version):
            return http_get("https://plugins.svn.wordpress.org/%s/tags/%s/%s" % (
                urllib.parse.quote(slug), urllib.parse.quote(version), urllib.parse.quote(rel)))
        baseline = Baseline(baseline_files, "wordpress.org plugin checksums (%s %s)" % (slug, version), reader)
        result = compare(baseline, files, {}, hasher, target_prefix=ext["path"] + "/")
        add_diffs(result, baseline, files, out, counter, budget)
        entry.update(status="ok", baseline=baseline.source, **truncate(result))
    return results


# --- vulnerabilities ----------------------------------------------------------------

CORE_CPE = {
    "wordpress": "cpe:2.3:a:wordpress:wordpress:{v}:*:*:*:*:*:*:*",
    "prestashop": "cpe:2.3:a:prestashop:prestashop:{v}:*:*:*:*:*:*:*",
    "drupal": "cpe:2.3:a:drupal:drupal:{v}:*:*:*:*:*:*:*",
    "joomla": "cpe:2.3:a:joomla:joomla\\!:{v}:*:*:*:*:*:*:*",
}
EXT_TARGET_SW = {"wordpress": "wordpress", "prestashop": "prestashop", "drupal": "drupal", "joomla": "joomla\\!"}
CORE_PACKAGES = {
    "prestashop": ["prestashop/prestashop"],
    "drupal": ["drupal/core", "drupal/drupal"],
    "joomla": ["joomla/joomla-cms"],
    "magento": ["magento/community-edition", "magento/product-community-edition", "magento/magento2-base"],
}


class Nvd:
    def __init__(self, budget):
        self.budget = budget
        self.key = os.environ.get("NVD_API_KEY")
        self.delay = NVD_DELAY_WITH_KEY if self.key else NVD_DELAY
        self.last = 0.0

    def query(self, match_string):
        wait = self.last + self.delay - time.monotonic()
        if wait > 0:
            if wait > self.budget.left():
                raise Unavailable("time budget exhausted before the NVD query")
            time.sleep(wait)
        self.budget.check("the NVD query")
        url = "%s?%s" % (NVD, urllib.parse.urlencode({"virtualMatchString": match_string, "resultsPerPage": 2000}))
        try:
            answer = http_json(url, {"apiKey": self.key} if self.key else None)
        finally:
            self.last = time.monotonic()
        return (answer or {}).get("vulnerabilities", [])


def cpe_product(cpe):
    parts = cpe.split(":")
    return parts[4] if len(parts) > 4 else ""


def cpe_version_matches(match, installed):
    """True when this NVD cpeMatch covers the installed version (exact value or range)."""
    version = match.get("criteria", "").split(":")[5] if len(match.get("criteria", "").split(":")) > 5 else "*"
    if version not in ("*", "-"):
        return version == installed
    v = parse_version(installed)
    if not v:
        return True
    checks = (("versionStartIncluding", lambda x: v[1] >= x), ("versionStartExcluding", lambda x: v[1] > x),
              ("versionEndIncluding", lambda x: v[1] <= x), ("versionEndExcluding", lambda x: v[1] < x))
    for key, test in checks:
        if match.get(key):
            bound = parse_version(match[key])
            if bound and bound[0] == v[0] and not test(bound[1]):
                return False
    return True


def nvd_affects(item, product, installed):
    """The CVE lists `product` itself as vulnerable at the installed version (not only as a platform)."""
    for config in item.get("cve", {}).get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and cpe_product(match.get("criteria", "")) == product \
                        and cpe_version_matches(match, installed):
                    return True
    return False


def nvd_entry(item, product):
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    cvss = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss = {"version": data.get("version"), "vector": data.get("vectorString"), "base_score": data.get("baseScore")}
            break
    fixed = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and cpe_product(match.get("criteria", "")) == product:
                    if match.get("versionEndExcluding"):
                        fixed.add(match["versionEndExcluding"])
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    return {"id": cve.get("id"), "aliases": [], "summary": description[:600], "published": cve.get("published"),
            "cvss_reference": cvss, "cwe": cwes, "fixed_in": sorted(fixed, key=lambda v: parse_version(v) or ("", ())),
            "references": [r.get("url") for r in cve.get("references", [])[:3]], "source": "NVD"}


def osv_query(package, version):
    body = json.dumps({"package": {"name": package, "ecosystem": "Packagist"}, "version": version}).encode()
    answer = http_json("https://api.osv.dev/v1/query", {"Content-Type": "application/json"}, body) or {}
    found = []
    for vuln in answer.get("vulns", []):
        fixed = sorted({e["fixed"] for a in vuln.get("affected", []) if a.get("package", {}).get("name") == package
                        for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e})
        severity = next((s for s in vuln.get("severity", []) if s.get("type", "").startswith("CVSS")), None)
        found.append({"id": vuln.get("id"), "aliases": vuln.get("aliases", []),
                      "summary": (vuln.get("summary") or vuln.get("details") or "")[:600], "published": vuln.get("published"),
                      "cvss_reference": {"vector": severity["score"]} if severity else None,
                      "fixed_in": fixed, "references": [r.get("url") for r in vuln.get("references", [])[:3]],
                      "source": "OSV (%s)" % package})
    return found


def wpscan(kind, slug, version):
    token = os.environ.get("WPSCAN_API_TOKEN")
    if not token:
        return None
    path = {"core": "wordpresses/%s" % version.replace(".", ""), "plugin": "plugins/%s" % slug, "theme": "themes/%s" % slug}[kind]
    answer = http_json("https://wpscan.com/api/v3/" + path, {"Authorization": "Token token=%s" % token}) or {}
    data = next(iter(answer.values()), {}) if answer else {}
    found = []
    for vuln in (data or {}).get("vulnerabilities", []):
        fixed = vuln.get("fixed_in")
        introduced = vuln.get("introduced_in")
        if kind != "core":
            if fixed and not is_newer(fixed, version):
                continue
            if introduced and is_newer(introduced, version):
                continue
        refs = vuln.get("references", {})
        found.append({"id": "WPScan-%s" % vuln.get("id"), "aliases": ["CVE-%s" % c for c in refs.get("cve", [])],
                      "summary": vuln.get("title", "")[:600], "published": vuln.get("created_at"),
                      "cvss_reference": vuln.get("cvss"), "fixed_in": [fixed] if fixed else [],
                      "references": (refs.get("url") or [])[:3], "source": "WPScan"})
    return found


def fixed_for(item, installed):
    """The first fixed version after the installed one, preferring the installed branch."""
    later = [v for v in item.get("fixed_in") or [] if is_newer(v, installed)]
    branch = [v for v in later if same_branch(v, installed)]
    pick = branch or later
    return min(pick, key=lambda v: parse_version(v)[1]) if pick else None


def merge_vulns(lists, installed=None):
    merged, index = [], {}
    for items in lists:
        for item in items:
            keys = {item["id"]} | set(item.get("aliases") or [])
            hit = next((index[k] for k in keys if k in index), None)
            if hit is None:
                merged.append(item)
                for k in keys:
                    index[k] = item
            else:
                hit["aliases"] = sorted((set(hit.get("aliases") or []) | keys) - {hit["id"]})
                hit["fixed_in"] = sorted(set(hit.get("fixed_in") or []) | set(item.get("fixed_in") or []),
                                         key=lambda v: parse_version(v) or ("", ()))
                hit["source"] = " + ".join(sorted(set(hit["source"].split(" + ")) | {item["source"]}))
                if not hit.get("cvss_reference"):
                    hit["cvss_reference"] = item.get("cvss_reference")
                for k in keys:
                    index[k] = hit
    for item in merged:
        item["fixed_for_installed"] = fixed_for(item, installed) if installed else None
    return merged


def vulnerabilities(found, offline, budget):
    if offline:
        return {"status": "not_checked", "reason": "offline mode"}
    cms, version = found["cms"], found.get("version")
    nvd = Nvd(budget)
    out = {"status": "ok", "core": {"component": cms, "version": version, "vulnerabilities": [], "sources": [],
                                    "not_checked": []}, "extensions": []}
    if not version:
        return {"status": "not_checked", "reason": "the installed version could not be read"}
    core = out["core"]
    lists = []
    if cms in CORE_CPE:
        try:
            product = cpe_product(CORE_CPE[cms])
            lists.append([nvd_entry(i, product) for i in nvd.query(CORE_CPE[cms].format(v=version))
                          if nvd_affects(i, product, version)])
            core["sources"].append("NVD")
        except Unavailable as exc:
            core["not_checked"].append("NVD: %s" % exc)
    for package in CORE_PACKAGES.get(cms, []):
        try:
            budget.check("OSV")
            lists.append(osv_query(package, version))
            core["sources"].append("OSV %s" % package)
        except Unavailable as exc:
            core["not_checked"].append("OSV %s: %s" % (package, exc))
    if cms == "wordpress":
        try:
            result = wpscan("core", None, version)
            if result is None:
                core["not_checked"].append("WPScan: WPSCAN_API_TOKEN not set")
            else:
                lists.append(result)
                core["sources"].append("WPScan")
        except Unavailable as exc:
            core["not_checked"].append("WPScan: %s" % exc)
    core["vulnerabilities"] = merge_vulns(lists, version)

    for ext in found.get("extensions", []):
        entry = {"component": "%s %s" % (ext["kind"], ext["slug"]), "slug": ext["slug"], "kind": ext["kind"],
                 "version": ext.get("version"), "vulnerabilities": [], "sources": [], "not_checked": []}
        out["extensions"].append(entry)
        if not ext.get("version"):
            entry["not_checked"].append("version not found in the extension's files")
            continue
        lists = []
        if cms == "wordpress" and ext["kind"] in ("plugin", "theme"):
            try:
                result = wpscan(ext["kind"], ext["slug"], ext["version"])
                if result is not None:
                    lists.append(result)
                    entry["sources"].append("WPScan")
            except Unavailable as exc:
                entry["not_checked"].append("WPScan: %s" % exc)
        if cms == "drupal":
            try:
                budget.check("OSV")
                lists.append(osv_query("drupal/%s" % ext["slug"], ext["version"].split("-", 1)[-1]))
                entry["sources"].append("OSV drupal/%s" % ext["slug"])
            except Unavailable as exc:
                entry["not_checked"].append("OSV: %s" % exc)
        if cms == "prestashop":
            try:
                budget.check("OSV")
                lists.append(osv_query("prestashop/%s" % ext["slug"], ext["version"]))
                entry["sources"].append("OSV prestashop/%s" % ext["slug"])
            except Unavailable as exc:
                entry["not_checked"].append("OSV: %s" % exc)
        bundled = ext.get("bundled") or (ext.get("author") or "").lower() in ("prestashop", "joomla! project")
        if cms in EXT_TARGET_SW and "WPScan" not in entry["sources"] and not (bundled and cms in ("prestashop", "joomla")):
            product = ext["slug"].split("/")[-1].replace("-", "_") if cms == "wordpress" else ext["slug"].split("/")[-1]
            if not re.match(r"^[A-Za-z0-9_.-]+$", product) or not re.match(r"^[A-Za-z0-9_.-]+$", ext["version"]):
                entry["not_checked"].append("NVD: name or version has characters CPE matching cannot use")
            else:
                match = "cpe:2.3:a:*:%s:%s:*:*:*:*:%s:*:*" % (product, ext["version"], EXT_TARGET_SW[cms])
                try:
                    lists.append([nvd_entry(i, product) for i in nvd.query(match)
                                  if nvd_affects(i, product, ext["version"])])
                    entry["sources"].append("NVD (product name %s)" % product)
                except Unavailable as exc:
                    entry["not_checked"].append("NVD: %s" % exc)
        elif bundled:
            entry["note"] = "shipped with %s: covered by the core advisories and OSV" % cms
        entry["vulnerabilities"] = merge_vulns(lists, ext["version"])
    if cms == "wordpress" and not os.environ.get("WPSCAN_API_TOKEN"):
        out["note"] = ("WordPress plugins and themes are matched in NVD by product name only; a plugin whose NVD name "
                       "differs from its slug is missed. Set WPSCAN_API_TOKEN for complete coverage.")
    return out


# --- updates --------------------------------------------------------------------------

TAG_FORMAT = {"joomla": r"^\d+\.\d+\.\d+$", "prestashop": r"^\d+\.\d+\.\d+(\.\d+)?$",
              "magento": r"^2\.\d+\.\d+(-p\d+)?$"}


def tag_versions(tags, fmt=r"^\d+(\.\d+)+$"):
    return [t.lstrip("vV") for t in tags if re.match(fmt, t.lstrip("vV")) and parse_version(t.lstrip("vV"))]


def update_entry(component, installed, versions=None, latest=None, **extra):
    latest = latest or (latest_of(versions, installed) if versions else None)
    entry = {"component": component, "installed": installed, "latest": latest,
             "latest_in_branch": latest_of(versions, installed, branch=True) if versions else None,
             "update_available": bool(latest and installed and is_newer(latest, installed))}
    entry.update(extra)
    return entry


def drupal_release_history(project, installed, legacy):
    channel = "7.x" if legacy else "current"
    body = http_get("https://updates.drupal.org/release-history/%s/%s" % (urllib.parse.quote(project), channel))
    if not body:
        return None
    if b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        raise Unavailable("updates.drupal.org returned XML with a DTD; ignored")
    root = ET.fromstring(body)
    status = (root.findtext("project_status") or "").strip()
    releases = []
    for release in root.iter("release"):
        if (release.findtext("status") or "published") != "published":
            continue
        version = (release.findtext("version") or "").strip()
        terms = [(t.findtext("value") or "") for t in release.iter("term")]
        releases.append((version, "Security update" in terms))
    versions = [v for v, _ in releases]
    security = sorted({v for v, sec in releases if sec and installed and is_newer(v, installed)},
                      key=lambda v: parse_version(v)[1])
    return update_entry(project, installed, versions, security_update_available=bool(security),
                        security_releases_after_installed=security[:10],
                        project_status=status or None,
                        unsupported=status in ("unsupported", "insecure", "revoked"))


def updates(found, offline, budget):
    if offline:
        return {"status": "not_checked", "reason": "offline mode"}
    cms, version = found["cms"], found.get("version")
    result = {"status": "ok", "core": None, "extensions": [], "not_checked": []}
    try:
        budget.check("the update check")
        if cms == "wordpress":
            offers = (http_json("https://api.wordpress.org/core/version-check/1.7/") or {}).get("offers", [])
            versions = [o.get("current") for o in offers if o.get("current")]
            stable = http_json("https://api.wordpress.org/core/stable-check/1.0/") or {}
            result["core"] = update_entry("wordpress", version, versions, status=stable.get(version))
        elif cms == "prestashop":
            result["core"] = update_entry("prestashop", version, tag_versions(git_tags("https://github.com/PrestaShop/PrestaShop.git"), TAG_FORMAT["prestashop"]))
        elif cms == "joomla":
            result["core"] = update_entry("joomla", version, tag_versions(git_tags("https://github.com/joomla/joomla-cms.git"), TAG_FORMAT["joomla"]))
        elif cms == "magento":
            result["core"] = update_entry("magento", version, tag_versions(git_tags("https://github.com/magento/magento2.git"), TAG_FORMAT["magento"]))
        elif cms == "drupal":
            result["core"] = drupal_release_history("drupal", version, found.get("legacy"))
    except (Unavailable, ET.ParseError) as exc:
        result["not_checked"].append("%s core: %s" % (cms, exc))

    for ext in found.get("extensions", []):
        name = "%s %s" % (ext["kind"], ext["slug"])
        if cms == "joomla" and ext.get("bundled"):
            continue
        if budget.left() <= 0:
            result["not_checked"].append("%s: time budget exhausted" % name)
            continue
        try:
            entry = None
            if cms == "wordpress" and ext["kind"] in ("plugin", "theme"):
                api = "plugins" if ext["kind"] == "plugin" else "themes"
                action = "plugin_information" if ext["kind"] == "plugin" else "theme_information"
                query = urllib.parse.urlencode({"action": action, "request[slug]": ext["slug"],
                                                "request[fields][sections]": 0, "request[fields][versions]": 0})
                info = http_json("https://api.wordpress.org/%s/info/1.2/?%s" % (api, query))
                if info and info.get("version") and not info.get("error"):
                    entry = update_entry(name, ext.get("version"), latest=info["version"],
                                         closed=bool(info.get("closed")))
                else:
                    result["not_checked"].append("%s: not published on wordpress.org" % name)
            elif cms == "drupal":
                entry = drupal_release_history(ext["slug"], ext.get("version"), found.get("legacy"))
                if entry:
                    entry["component"] = name
                else:
                    result["not_checked"].append("%s: not a drupal.org project" % name)
            elif cms == "prestashop" and ext["kind"] == "module" and (ext.get("author") or "").lower() == "prestashop":
                entry = update_entry(name, ext.get("version"),
                                     tag_versions(git_tags("https://github.com/PrestaShop/%s.git" % ext["slug"])))
            else:
                result["not_checked"].append("%s: no public release source" % name)
            if entry:
                result["extensions"].append(entry)
        except (Unavailable, ET.ParseError) as exc:
            result["not_checked"].append("%s: %s" % (name, exc))
    return result


# --- commands -------------------------------------------------------------------------

def summary(report):
    integ = report.get("integrity") or {}
    vulns = report.get("vulnerabilities") or {}
    upd = report.get("updates") or {}
    vuln_count = len((vulns.get("core") or {}).get("vulnerabilities", [])) + sum(
        len(e["vulnerabilities"]) for e in vulns.get("extensions", []))
    outdated = [e["component"] for e in [upd.get("core")] + list(upd.get("extensions", [])) if e and e.get("update_available")]
    return {"cms": report["cms"], "version": report.get("version"), "root": report.get("root"),
            "extensions": len(report.get("extensions", [])),
            "integrity": integ.get("status"),
            "modified_files": integ.get("modified_count", 0), "added_files": integ.get("added_count", 0),
            "code_in_upload_dirs": integ.get("code_in_upload_dirs_count", 0),
            "modified_extension_files": sum(e.get("modified_count", 0) for e in report.get("extension_integrity", [])),
            "known_vulnerabilities": vuln_count, "outdated_components": outdated,
            "report": report.get("file")}


def cmd_detect(args):
    found = detect(args.path)
    print(json.dumps(found or {"cms": None}, indent=2, ensure_ascii=False))
    return 0


def cmd_scan(args):
    data = common.data_dir(args.data)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    budget = Budget(args.budget)
    if args.path:
        found = detect(args.path)
        if not found:
            print(json.dumps({"cms": None, "path": os.path.abspath(args.path)}))
            return 0
    elif args.cms and args.version:
        found = sanitize({"cms": args.cms, "version": args.version, "root": None, "extensions": [],
                          "legacy": args.cms == "drupal" and args.version.startswith("7.")})
        if not found["version"]:
            print("unusable --version", file=sys.stderr)
            return 2
    else:
        print("give a PATH, or --cms and --version", file=sys.stderr)
        return 2
    report = dict(found, untrusted_fields=["extensions[].name", "extensions[].author", "diffs"],
                  generated=common.now_iso())
    if found.get("root"):
        report["integrity"], report["extension_integrity"] = integrity(found, data, out, args.offline, budget)
    else:
        report["integrity"] = {"status": "not_checked", "reason": "no files (website audit)"}
        report["extension_integrity"] = []
    report["vulnerabilities"] = vulnerabilities(found, args.offline, budget)
    report["updates"] = updates(found, args.offline, budget)
    report["file"] = os.path.join(out, "cms.json")
    common.write_json(report["file"], report)
    print(json.dumps(summary(report), indent=2, ensure_ascii=False))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("detect", allow_abbrev=False)
    p.add_argument("path")
    p.set_defaults(func=cmd_detect)
    p = sub.add_parser("scan", allow_abbrev=False)
    p.add_argument("path", nargs="?")
    p.add_argument("--data")
    p.add_argument("--out", required=True, help="folder for cms.json and diffs/, inside the engagement folder")
    p.add_argument("--cms", choices=["wordpress", "prestashop", "drupal", "joomla", "magento"])
    p.add_argument("--version")
    p.add_argument("--budget", type=int, default=300, help="seconds for all network checks (default 300)")
    p.add_argument("--offline", action="store_true", help="no network: detection, and integrity from cached archives")
    p.set_defaults(func=cmd_scan)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

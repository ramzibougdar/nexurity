#!/usr/bin/env python3
"""Find and install the audit tools Nexurity uses.

    tools.py where   --data D                 where each tool is (PATH first, then Nexurity's folder)
    tools.py install --data D [--only a,b]    install the missing tools, without asking
    tools.py install --data D --first-run     same, but only for tools never attempted before
    tools.py install --data D --upgrade       also update the tools Nexurity installed (and Homebrew ones)

Installation never uses sudo and never changes the target:
- with Homebrew (macOS, Linuxbrew): `brew install <formula>`;
- otherwise in Nexurity's data folder (`<data>/venv`, `<data>/bin`, `<data>/tools`):
  semgrep and pip-audit in a private Python virtual environment; gitleaks and trufflehog from their
  official GitHub release, checked against the release's SHA-256 checksums; lynis and testssl.sh from their
  official repositories;
- cargo-audit with `cargo install` only when Rust is installed (it is only needed for Rust projects);
- CodeQL from the official CodeQL bundle (CLI and standard queries, github/codeql-action releases),
  checked against its published SHA-256, in `<data>/tools/codeql`. Its licence is free for open-source
  code; closed-source code needs a GitHub Advanced Security licence;
- codeql-php (PHP support for CodeQL, Vozec/codeql-php, MIT) at a pinned commit, built with Rust's
  `cargo` in `<data>/tools/codeql-php`; Rust is installed with Homebrew when it is missing and Homebrew is
  there, otherwise codeql-php is skipped.

A tool that cannot be installed is reported and the audit goes on without it. Python standard library only.
"""
import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

TOOLS = ["semgrep", "pip-audit", "gitleaks", "trufflehog", "lynis", "testssl.sh", "cargo-audit", "codeql",
         "codeql-php"]
ALL_TOOLS = TOOLS
ALIASES = {"testssl.sh": ["testssl.sh", "testssl"]}
BREW_FORMULA = {"semgrep": "semgrep", "pip-audit": "pip-audit", "gitleaks": "gitleaks", "trufflehog": "trufflehog",
                "lynis": "lynis", "testssl.sh": "testssl", "cargo-audit": "cargo-audit"}
PYPI = {"semgrep": "semgrep", "pip-audit": "pip-audit"}
RELEASES = {
    "gitleaks": {"repo": "gitleaks/gitleaks", "asset": "gitleaks_{v}_{os}_{arch}.tar.gz",
                 "checksums": "gitleaks_{v}_checksums.txt", "arch": {"x86_64": "x64", "arm64": "arm64"}},
    "trufflehog": {"repo": "trufflesecurity/trufflehog", "asset": "trufflehog_{v}_{os}_{arch}.tar.gz",
                   "checksums": "trufflehog_{v}_checksums.txt", "arch": {"x86_64": "amd64", "arm64": "arm64"}},
}
SOURCES = {
    "lynis": {"repo": "CISOfy/lynis", "branch": None, "entry": "lynis"},
    "testssl.sh": {"repo": "testssl/testssl.sh", "branch": "3.2", "entry": "testssl.sh"},
}
EXTRA_PATHS = ["/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin",
               os.path.join(os.path.expanduser("~"), ".cargo", "bin"),
               os.path.join(os.path.expanduser("~"), ".local", "bin")]
NEEDS = {"testssl.sh": ["openssl", "hexdump"], "lynis": ["sh"]}
USER_AGENT = "nexurity-tools (+https://github.com/ramzibougdar/nexurity)"
TIMEOUT = 60
MAX_DOWNLOAD = 300 << 20
CODEQL_PHP = {"repo": "https://github.com/Vozec/codeql-php.git",
              "commit": "448ec77f9d5286d38c20ecc5fa79bd58a4128432"}
CODEQL_PLATFORM = {"linux": "linux64", "darwin": "osx64"}
CODEQL_BUNDLE = {"repo": "github/codeql-action", "tag": r"^codeql-bundle-v\d+\.\d+\.\d+$",
                 "asset": {"linux": "codeql-bundle-linux64.tar.gz", "darwin": "codeql-bundle-osx64.tar.gz"}}
MAX_BUNDLE = 3 << 30
FREE_SPACE_NEEDED = 6 << 30


class InstallError(Exception):
    pass


# --- finding the tools ------------------------------------------------------------------

def codeql_php_dir(data):
    return os.path.join(data, "tools", "codeql-php")


def find(tool, data):
    if tool == "codeql-php":
        root = codeql_php_dir(data)
        built = [os.path.join(root, "php", "tools", p, "extractor") for p in CODEQL_PLATFORM.values()]
        return root if any(os.path.isfile(b) for b in built) else None
    names = ALIASES.get(tool, [tool])
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for folder in common.managed_tool_dirs(data) + EXTRA_PATHS:
        for name in names:
            path = os.path.join(folder, name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    return None


def where(data):
    return {tool: find(tool, data) for tool in ALL_TOOLS}


# --- helpers -----------------------------------------------------------------------------

def run(command, timeout, env=None):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                env=dict(os.environ, **(env or {})))
    except subprocess.TimeoutExpired:
        raise InstallError("%s took more than %d s" % (os.path.basename(command[0]), timeout))
    except OSError as exc:
        raise InstallError(str(exc))
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()[-3:]
        raise InstallError("%s failed: %s" % (" ".join(os.path.basename(c) for c in command[:3]), " / ".join(tail)[:300]))
    return result.stdout


def http_get(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            data = response.read(MAX_DOWNLOAD + 1)
    except urllib.error.HTTPError as exc:
        raise InstallError("download refused (HTTP %s): %s" % (exc.code, url))
    except (urllib.error.URLError, OSError) as exc:
        raise InstallError("download failed (%s): %s" % (exc, url))
    if len(data) > MAX_DOWNLOAD:
        raise InstallError("download too large: %s" % url)
    return data


def platform_names():
    system = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
    machine = platform.machine().lower()
    arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if not system or not arch:
        raise InstallError("no official build for %s %s" % (sys.platform, machine))
    return system, arch


def version_key(tag):
    return tuple(int(n) for n in re.findall(r"\d+", tag))


def latest_tag(repo):
    """Latest release tag, from Git tags (no GitHub API quota)."""
    if shutil.which("git"):
        out = run(["git", "ls-remote", "--tags", "--refs", "https://github.com/%s.git" % repo], 30,
                  {"GIT_TERMINAL_PROMPT": "0"})
        tags = [line.split("refs/tags/", 1)[1] for line in out.splitlines() if "refs/tags/" in line]
        tags = [t for t in tags if re.match(r"^v?\d+\.\d+\.\d+$", t)]
        if tags:
            return max(tags, key=version_key)
    request = urllib.request.Request("https://github.com/%s/releases/latest" % repo, method="HEAD",
                                     headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            final = response.geturl()
    except (urllib.error.URLError, OSError) as exc:
        raise InstallError("latest release of %s unknown (%s)" % (repo, exc))
    m = re.search(r"/tag/([^/]+)$", final)
    if not m:
        raise InstallError("latest release of %s unknown" % repo)
    return m.group(1)


def write_executable(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    with os.fdopen(fd, "wb") as fh:
        fh.write(content)
    os.chmod(tmp, 0o755)
    os.replace(tmp, path)


def safe_members(archive):
    """(relative path, member) for regular files and folders, top folder stripped, no escape."""
    for member in archive.getmembers():
        parts = member.name.replace("\\", "/").split("/")[1:]
        if not parts or member.name.startswith("/") or ".." in parts or not (member.isfile() or member.isdir()):
            continue
        yield "/".join(p for p in parts if p), member


# --- install methods ---------------------------------------------------------------------

def brew_path():
    for candidate in [shutil.which("brew"), "/opt/homebrew/bin/brew", "/usr/local/bin/brew",
                      "/home/linuxbrew/.linuxbrew/bin/brew"]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def install_brew(tool, brew):
    run([brew, "install", BREW_FORMULA[tool]], 900,
        {"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ENV_HINTS": "1", "NONINTERACTIVE": "1"})


def install_pypi(tool, data):
    venv = os.path.join(data, "venv")
    python = os.path.join(venv, "bin", "python")
    if not os.path.exists(python):
        run([sys.executable, "-m", "venv", venv], 300)
    run([python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--timeout", "60",
         "--retries", "3", "--upgrade", PYPI[tool]], 900)


def install_release(tool, data):
    spec = RELEASES[tool]
    system, arch = platform_names()
    tag = latest_tag(spec["repo"])
    version = tag.lstrip("v")
    asset = spec["asset"].format(v=version, os=system, arch=spec["arch"][arch])
    base = "https://github.com/%s/releases/download/%s/" % (spec["repo"], tag)
    checksums = http_get(base + spec["checksums"].format(v=version)).decode("utf-8", "replace")
    expected = None
    for line in checksums.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip("*") == asset:
            expected = fields[0].lower()
    if not expected:
        raise InstallError("%s is not listed in the release checksums" % asset)
    archive_bytes = http_get(base + asset)
    if hashlib.sha256(archive_bytes).hexdigest() != expected:
        raise InstallError("checksum mismatch for %s: not installed" % asset)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        member = next((m for m in archive.getmembers() if m.isfile() and os.path.basename(m.name) == tool), None)
        if member is None:
            raise InstallError("%s not found in %s" % (tool, asset))
        content = archive.extractfile(member).read()
    write_executable(os.path.join(data, "bin", tool), content)
    return version


def install_source(tool, data):
    spec = SOURCES[tool]
    target = os.path.join(data, "tools", tool)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    staging = tempfile.mkdtemp(dir=os.path.dirname(target), prefix=".tmp-")
    try:
        if shutil.which("git"):
            command = ["git", "clone", "--quiet", "--depth", "1"]
            if spec["branch"]:
                command += ["--branch", spec["branch"]]
            run(command + ["https://github.com/%s.git" % spec["repo"], os.path.join(staging, "src")], 300,
                {"GIT_TERMINAL_PROMPT": "0"})
            shutil.rmtree(os.path.join(staging, "src", ".git"), ignore_errors=True)
            source = os.path.join(staging, "src")
        else:
            ref = "refs/heads/%s" % (spec["branch"] or "master")
            data_bytes = http_get("https://codeload.github.com/%s/tar.gz/%s" % (spec["repo"], ref))
            source = os.path.join(staging, "src")
            with tarfile.open(fileobj=io.BytesIO(data_bytes), mode="r:gz") as archive:
                for rel, member in safe_members(archive):
                    path = os.path.join(source, rel)
                    if member.isdir():
                        os.makedirs(path, exist_ok=True)
                        continue
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as fh:
                        fh.write(archive.extractfile(member).read())
                    os.chmod(path, 0o755 if member.mode & 0o111 else 0o644)
        entry = os.path.join(source, spec["entry"])
        if not os.path.isfile(entry):
            raise InstallError("%s not found in the downloaded sources" % spec["entry"])
        os.chmod(entry, 0o755)
        if os.path.exists(target):
            shutil.rmtree(target)
        os.replace(source, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def download_file(url, path, limit, digest):
    """Stream a large download to `path`, returning its SHA-256."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response, open(path, "wb") as out:
            for chunk in iter(lambda: response.read(1 << 20), b""):
                size += len(chunk)
                if size > limit:
                    raise InstallError("download too large: %s" % url)
                digest.update(chunk)
                out.write(chunk)
    except urllib.error.HTTPError as exc:
        raise InstallError("download refused (HTTP %s): %s" % (exc.code, url))
    except (urllib.error.URLError, OSError) as exc:
        raise InstallError("download failed (%s): %s" % (exc, url))
    return digest.hexdigest()


def extract_tree(archive, target):
    """Extract a tar archive under `target`, top folder stripped; links only when they stay inside."""
    root = os.path.realpath(target)
    for member in archive:
        parts = member.name.replace("\\", "/").split("/")[1:]
        rel = "/".join(p for p in parts if p)
        if not rel or member.name.startswith("/") or ".." in parts:
            continue
        path = os.path.join(target, rel)
        if member.isdir():
            os.makedirs(path, exist_ok=True)
        elif member.isfile():
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with archive.extractfile(member) as src, open(path, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            os.chmod(path, 0o755 if member.mode & 0o111 else 0o644)
        elif member.issym():
            link = os.path.realpath(os.path.join(os.path.dirname(path), member.linkname))
            if link == root or link.startswith(root + os.sep):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                if os.path.lexists(path):
                    os.unlink(path)
                os.symlink(member.linkname, path)


def install_codeql(data):
    system, _arch = platform_names()
    asset = CODEQL_BUNDLE["asset"][system]
    tools_dir = os.path.join(data, "tools")
    os.makedirs(tools_dir, exist_ok=True)
    if shutil.disk_usage(tools_dir).free < FREE_SPACE_NEEDED:
        raise InstallError("CodeQL needs about %d GB of free disk space" % (FREE_SPACE_NEEDED >> 30))
    out = run(["git", "ls-remote", "--tags", "--refs", "https://github.com/%s.git" % CODEQL_BUNDLE["repo"]], 60,
              {"GIT_TERMINAL_PROMPT": "0"}) if shutil.which("git") else ""
    tags = [l.split("refs/tags/", 1)[1] for l in out.splitlines() if "refs/tags/" in l]
    tags = [t for t in tags if re.match(CODEQL_BUNDLE["tag"], t)]
    tag = max(tags, key=version_key) if tags else latest_tag(CODEQL_BUNDLE["repo"])
    base = "https://github.com/%s/releases/download/%s/" % (CODEQL_BUNDLE["repo"], tag)
    listed = http_get(base + asset + ".checksum.txt").decode("utf-8", "replace").split()
    if len(listed) < 2 or listed[1].lstrip("*") != asset or not re.match(r"^[0-9a-f]{64}$", listed[0]):
        raise InstallError("unexpected checksum file for %s" % asset)
    staging = tempfile.mkdtemp(dir=tools_dir, prefix=".tmp-")
    try:
        archive_path = os.path.join(staging, asset)
        if download_file(base + asset, archive_path, MAX_BUNDLE, hashlib.sha256()) != listed[0]:
            raise InstallError("checksum mismatch for %s: not installed" % asset)
        source = os.path.join(staging, "codeql")
        with tarfile.open(archive_path, mode="r:gz") as archive:
            extract_tree(archive, source)
        os.unlink(archive_path)
        if not os.path.isfile(os.path.join(source, "codeql")):
            raise InstallError("codeql not found in %s" % asset)
        target = os.path.join(tools_dir, "codeql")
        if os.path.exists(target):
            shutil.rmtree(target)
        os.replace(source, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return tag.rsplit("-v", 1)[-1]


def cargo_path():
    for candidate in [shutil.which("cargo"), os.path.join(os.path.expanduser("~"), ".cargo", "bin", "cargo"),
                      "/opt/homebrew/bin/cargo", "/usr/local/bin/cargo"]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def install_codeql_php(data, brew):
    """Fetch codeql-php at its pinned commit and build its extractor with cargo."""
    if not find("codeql", data):
        raise InstallError("needs CodeQL, which is not installed")
    cargo = cargo_path()
    if not cargo and brew:
        run([brew, "install", "rust"], 1800, {"HOMEBREW_NO_AUTO_UPDATE": "1", "NONINTERACTIVE": "1"})
        cargo = cargo_path()
    if not cargo:
        raise InstallError("needs Rust (cargo) to build: install Rust from https://rustup.rs, then run /nexurity:setup")
    if not shutil.which("git"):
        raise InstallError("needs git")
    system, _arch = platform_names()
    tools_dir = os.path.join(data, "tools")
    os.makedirs(tools_dir, exist_ok=True)
    staging = tempfile.mkdtemp(dir=tools_dir, prefix=".tmp-")
    try:
        source = os.path.join(staging, "codeql-php")
        env = {"GIT_TERMINAL_PROMPT": "0"}
        run(["git", "init", "-q", source], 60, env)
        run(["git", "-C", source, "fetch", "-q", "--depth", "1", CODEQL_PHP["repo"], CODEQL_PHP["commit"]], 600, env)
        run(["git", "-C", source, "checkout", "-q", "FETCH_HEAD"], 120, env)
        head = run(["git", "-C", source, "rev-parse", "HEAD"], 60, env).strip()
        if head != CODEQL_PHP["commit"]:
            raise InstallError("codeql-php: unexpected commit %s" % head[:12])
        build_env = {"CODEQL_PLATFORM": CODEQL_PLATFORM[system],
                     "PATH": os.path.dirname(cargo) + os.pathsep + os.environ.get("PATH", "")}
        run(["bash", os.path.join(source, "php", "build.sh")], 3600, build_env)
        shutil.rmtree(os.path.join(source, "target"), ignore_errors=True)
        shutil.rmtree(os.path.join(source, ".git"), ignore_errors=True)
        if not os.path.isfile(os.path.join(source, "php", "tools", CODEQL_PLATFORM[system], "extractor")):
            raise InstallError("codeql-php: the build produced no extractor")
        with open(os.path.join(source, ".nexurity-commit"), "w") as fh:
            fh.write(CODEQL_PHP["commit"] + "\n")
        target = codeql_php_dir(data)
        if os.path.exists(target):
            shutil.rmtree(target)
        os.replace(source, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return CODEQL_PHP["commit"][:12]


def install_cargo(tool):
    cargo = shutil.which("cargo") or os.path.join(os.path.expanduser("~"), ".cargo", "bin", "cargo")
    run([cargo, "install", "--locked", "--quiet", tool], 1800)


def install_one(tool, data, brew):
    """Install one tool; returns (method, error or None)."""
    errors = []
    if tool == "cargo-audit" and not (shutil.which("cargo") or os.path.exists(os.path.join(os.path.expanduser("~"), ".cargo", "bin", "cargo"))):
        return "skipped", "Rust (cargo) is not installed: only needed to audit Rust projects"
    if brew and tool in BREW_FORMULA:
        try:
            install_brew(tool, brew)
            if find(tool, data):
                return "brew", None
        except InstallError as exc:
            errors.append(str(exc))
    try:
        if tool in PYPI:
            install_pypi(tool, data)
            method = "private Python environment"
        elif tool in RELEASES:
            method = "official release %s (SHA-256 checked)" % install_release(tool, data)
        elif tool in SOURCES:
            install_source(tool, data)
            method = "official repository"
        elif tool == "cargo-audit":
            install_cargo(tool)
            method = "cargo install"
        elif tool == "codeql":
            method = "official CodeQL bundle %s (SHA-256 checked)" % install_codeql(data)
        elif tool == "codeql-php":
            method = "Vozec/codeql-php at commit %s, built with cargo" % install_codeql_php(data, brew)
        else:
            return "skipped", "no installer"
    except InstallError as exc:
        errors.append(str(exc))
        return "failed", "; ".join(errors)
    if not find(tool, data):
        errors.append("installed but not found afterwards")
        return "failed", "; ".join(errors)
    return method, None


def upgrade_one(tool, path, data, brew):
    """Update a tool that is already there, when Nexurity or Homebrew installed it."""
    if tool == "codeql-php":
        try:
            with open(os.path.join(path, ".nexurity-commit")) as fh:
                installed = fh.read().strip()
        except OSError:
            installed = ""
        if installed == CODEQL_PHP["commit"]:
            return "up to date (pinned commit %s)" % installed[:12]
        install_codeql_php(data, brew)
        return "updated to the pinned commit %s" % CODEQL_PHP["commit"][:12]
    real = os.path.realpath(path)
    if any(real.startswith(os.path.realpath(d) + os.sep) for d in common.managed_tool_dirs(data)):
        if tool in PYPI:
            install_pypi(tool, data)
        elif tool in RELEASES:
            install_release(tool, data)
        elif tool in SOURCES:
            install_source(tool, data)
        elif tool == "codeql":
            install_codeql(data)
        return "updated (Nexurity's folder)"
    if brew and "/Cellar/" in real and tool in BREW_FORMULA:
        run([brew, "upgrade", BREW_FORMULA[tool]], 900, {"HOMEBREW_NO_AUTO_UPDATE": "1", "NONINTERACTIVE": "1"})
        return "updated (Homebrew)"
    return None


def install(data, only=None, first_run=False, upgrade=False):
    marker = os.path.join(data, "tools-setup.json")
    previous = common.read_json(marker, {}) or {}
    attempted = set(previous.get("attempted") or [r.get("tool") for r in previous.get("results", [])])
    wanted = [t for t in TOOLS if (not only or t in only) and not (first_run and t in attempted)]
    if first_run and not wanted:
        return {"skipped": "already attempted on %s: run /nexurity:setup to try again" % previous.get("date", "a previous run"),
                "tools": where(data)}
    brew = brew_path()
    results = []
    for tool in wanted:
        present = find(tool, data)
        if present:
            entry = {"tool": tool, "status": "present", "path": present}
            if upgrade:
                try:
                    done = upgrade_one(tool, present, data, brew)
                    entry["status"] = done or "present (installed outside Nexurity: update it with its own installer)"
                except InstallError as exc:
                    entry.update(status="present", reason="update failed: %s" % exc)
            results.append(entry)
            continue
        method, error = install_one(tool, data, brew)
        entry = {"tool": tool, "status": "installed" if error is None and method != "skipped" else method,
                 "method": method if error is None else None, "path": find(tool, data)}
        if error:
            entry["reason"] = error
        results.append(entry)
    for entry in results:
        lacking = [c for c in NEEDS.get(entry["tool"], []) if not shutil.which(c)]
        if entry.get("path") and lacking:
            entry["warning"] = "needs %s, which is not installed (system package)" % ", ".join(lacking)
    report = {"date": common.now_iso(), "brew": bool(brew), "results": results,
              "attempted": sorted(attempted | {r["tool"] for r in results})}
    common.write_json(marker, report)
    return report


# --- command line ------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("where", allow_abbrev=False)
    p.add_argument("--data")
    p = sub.add_parser("install", allow_abbrev=False)
    p.add_argument("--data")
    p.add_argument("--only", help="comma-separated tool names")
    p.add_argument("--first-run", action="store_true", help="do nothing if an installation was already attempted")
    p.add_argument("--upgrade", action="store_true", help="also update the tools that are already there")
    args = parser.parse_args(argv)
    data = common.data_dir(args.data)
    if args.command == "where":
        print(json.dumps(where(data), indent=2))
        return 0
    only = {t.strip() for t in args.only.split(",")} if args.only else None
    print(json.dumps(install(data, only, args.first_run, args.upgrade), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

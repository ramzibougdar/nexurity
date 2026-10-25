#!/usr/bin/env python3
"""Check for new versions of Nexurity, its ported source and the audit tools.

    check_updates.py --data D [--full] [--json]

Fast and non-blocking: 15 seconds maximum, checks in parallel, offline-safe. The
result is cached in `<data>/update-check.json` for `update_check_cache_hours` (6 by
default); `--full` ignores the cache. GitHub API calls are kept to a minimum
(Git, raw.githubusercontent.com and PyPI are used first) and an exhausted quota is
reported, never waited for. Nothing is ever updated here. Python standard library only.
"""
import argparse
import concurrent.futures
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import tools  # noqa: E402

REPO = "ramzibougdar/nexurity"
RAW_PLUGIN_JSON = "https://raw.githubusercontent.com/%s/main/plugins/nexurity/.claude-plugin/plugin.json" % REPO
TIMEOUT = 5
BUDGET = 15


class QuotaExhausted(Exception):
    pass


def http_json(url):
    headers = {"User-Agent": "nexurity-check-updates", "Accept": "application/json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429) and exc.headers.get("X-RateLimit-Remaining") == "0":
            reset = exc.headers.get("X-RateLimit-Reset")
            when = datetime.datetime.fromtimestamp(int(reset)).strftime("%H:%M") if reset else "later"
            raise QuotaExhausted("GitHub quota exhausted, reset at %s" % when)
        raise


def version_tuple(value):
    return tuple(int(n) for n in re.findall(r"\d+", str(value or ""))[:4])


def local_plugin_version():
    manifest = common.read_json(os.path.join(common.PLUGIN_ROOT, ".claude-plugin", "plugin.json"), {}) or {}
    return manifest.get("version", "0")


def check_nexurity():
    current = local_plugin_version()
    latest = http_json(RAW_PLUGIN_JSON).get("version")
    newer = version_tuple(latest) > version_tuple(current)
    return {"item": "Nexurity", "current": current, "latest": latest, "new": newer,
            "how": "claude plugin update nexurity@nexurity-marketplace (or /plugin)" if newer else None}


def check_source(source):
    current = source["commit"]
    latest = None
    if shutil.which("git"):
        result = subprocess.run(["git", "ls-remote", source["url"], "refs/heads/%s" % source.get("branch", "main")],
                                capture_output=True, text=True, timeout=TIMEOUT)
        if result.returncode == 0 and result.stdout.strip():
            latest = result.stdout.split()[0]
    if latest is None:
        owner_repo = source["url"].split("github.com/")[1].strip("/")
        latest = http_json("https://api.github.com/repos/%s/commits/%s" % (owner_repo, source.get("branch", "main")))["sha"]
    return {"item": source["name"], "current": current[:12], "latest": latest[:12], "new": latest != current,
            "how": "review the upstream diff before porting it (see NOTICE.md)" if latest != current else None,
            "affects": source.get("used_in", [])}


def installed_version(command, data=None):
    path = tools.find(command[0], data) if data else shutil.which(command[0])
    if not path:
        return None
    try:
        result = subprocess.run([path] + command[1:], capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"\d+\.\d+(?:\.\d+)?", result.stdout + result.stderr)
    return match.group(0) if match else "unknown"


def check_tool(tool, data=None):
    current = installed_version(tool["version_command"], data)
    if current is None:
        return {"item": tool["name"], "current": None, "latest": None, "new": False, "missing": True}
    latest = None
    if tool.get("check") == "pypi":
        latest = http_json("https://pypi.org/pypi/%s/json" % tool["package"])["info"]["version"]
    elif tool.get("check") == "github":
        latest = http_json("https://api.github.com/repos/%s/releases/latest" % tool["repo"])["tag_name"].lstrip("v")
    newer = bool(latest) and current != "unknown" and version_tuple(latest) > version_tuple(current)
    return {"item": tool["name"], "current": current, "latest": latest, "new": newer,
            "how": "update it with the tool's own installer, or brew upgrade (Homebrew); tools installed by "
                   "/nexurity:setup are updated by running it again" if newer else None}


def run_checks(data=None):
    lock = common.read_json(os.path.join(common.PLUGIN_ROOT, "sources.lock.json"), {}) or {}
    jobs = [("nexurity", check_nexurity, None)]
    jobs += [("source", check_source, s) for s in lock.get("sources", [])]
    jobs += [("tool", lambda t: check_tool(t, data), t) for t in lock.get("tools", [])]
    results, problems = [], []
    deadline = time.monotonic() + BUDGET
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn, arg) if arg is not None else pool.submit(fn): (kind, arg) for kind, fn, arg in jobs}
        for future, (kind, arg) in futures.items():
            name = (arg or {}).get("name", "Nexurity")
            try:
                results.append(future.result(timeout=max(0.1, deadline - time.monotonic())))
            except QuotaExhausted as exc:
                problems.append({"item": name, "status": "not checked (%s)" % exc})
            except Exception as exc:  # offline, timeout, unexpected answer: never block the audit
                problems.append({"item": name, "status": "not checked (%s)" % exc.__class__.__name__})
    return {"checked_at": common.now_iso(), "results": results, "not_checked": problems,
            "vulnerability_databases": "fetched online by the dependency audit tools at audit time: nothing to update"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data")
    parser.add_argument("--full", action="store_true", help="ignore the cache")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    data = common.data_dir(args.data)
    config = common.load_config(data)
    cache_path = os.path.join(data, "update-check.json")
    cached = common.read_json(cache_path)
    report = None
    if cached and not args.full:
        try:
            age = datetime.datetime.now().astimezone() - datetime.datetime.fromisoformat(cached["checked_at"])
            if age.total_seconds() < float(config.get("update_check_cache_hours", 6)) * 3600:
                report = dict(cached, cached=True)
        except (KeyError, ValueError):
            report = None
    if report is None:
        report = run_checks(data)
        report["cached"] = False
        common.write_json(cache_path, report)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    new = [r for r in report["results"] if r.get("new")]
    missing = [r["item"] for r in report["results"] if r.get("missing")]
    prefix = "(cached %s) " % report["checked_at"] if report.get("cached") else ""
    if not new:
        print(prefix + "Sources and tools up to date.")
    for r in new:
        print(prefix + "New version: %s %s -> %s. %s" % (r["item"], r["current"], r["latest"], r.get("how") or ""))
    if missing:
        print("Tools not installed: %s. Install them with /nexurity:setup." % ", ".join(missing))
    for p in report["not_checked"]:
        print("%s: %s" % (p["item"], p["status"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

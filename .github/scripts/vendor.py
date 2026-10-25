#!/usr/bin/env python3
"""Copy the third-party security skills listed in plugins/nexurity/vendor/SOURCES.json.

    python3 .github/scripts/vendor.py            # fetch each source at its pinned commit and copy it
    python3 .github/scripts/vendor.py --update   # move each source to the latest commit of its branch first
    python3 .github/scripts/vendor.py --check    # only verify the vendored files against their sources

Files are copied unmodified, with the source's licence files, into plugins/nexurity/vendor/<dir>/.
Nothing is executed from the sources. A maintainer reviews the diff before committing an update.
"""
import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VENDOR = os.path.join(ROOT, "plugins", "nexurity", "vendor")
MANIFEST = os.path.join(VENDOR, "SOURCES.json")


def git(*args, cwd=None):
    return subprocess.run(["git"] + list(args), cwd=cwd, check=True, capture_output=True, text=True,
                          env=dict(os.environ, GIT_TERMINAL_PROMPT="0")).stdout.strip()


def fetch(source, workdir, update):
    git("init", "-q", workdir)
    git("remote", "add", "origin", source["repo"] + ".git", cwd=workdir)
    ref = source["branch"] if update else source["commit"]
    git("fetch", "-q", "--depth", "1", "origin", ref, cwd=workdir)
    git("checkout", "-q", "FETCH_HEAD", cwd=workdir)
    return git("rev-parse", "HEAD", cwd=workdir)


def selected(workdir, patterns):
    files = []
    for dirpath, dirnames, names in os.walk(workdir):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in names:
            rel = os.path.relpath(os.path.join(dirpath, name), workdir).replace(os.sep, "/")
            if any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p.replace("**/", "")) for p in patterns):
                files.append(rel)
    return sorted(files)


def copy(source, workdir, target):
    if os.path.exists(target):
        shutil.rmtree(target)
    for rel in selected(workdir, source["include"]) + source["license_files"]:
        src = os.path.join(workdir, rel)
        if os.path.islink(src) or not os.path.isfile(src):
            raise SystemExit("%s: %s is missing or not a regular file" % (source["name"], rel))
        dst = os.path.join(target, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o644)


def same_tree(a, b):
    def listing(root):
        out = {}
        for dirpath, _dirs, names in os.walk(root):
            for name in names:
                path = os.path.join(dirpath, name)
                with open(path, "rb") as fh:
                    out[os.path.relpath(path, root)] = fh.read()
        return out
    return listing(a) == listing(b)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    with open(MANIFEST, encoding="utf-8") as fh:
        manifest = json.load(fh)
    status = 0
    for source in manifest["sources"]:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = os.path.join(tmp, "src")
            commit = fetch(source, workdir, args.update)
            target = os.path.join(VENDOR, source["dir"])
            if args.check:
                staged = os.path.join(tmp, "staged")
                copy(source, workdir, staged)
                ok = same_tree(staged, target)
                print("%s %s" % ("ok     " if ok else "DIFFERS", source["name"]))
                status |= 0 if ok else 1
                continue
            copy(source, workdir, target)
            if commit != source["commit"]:
                print("%s: %s -> %s" % (source["name"], source["commit"][:12], commit[:12]))
                source["commit"] = commit
    if not args.check:
        with open(MANIFEST, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    return status


if __name__ == "__main__":
    sys.exit(main())

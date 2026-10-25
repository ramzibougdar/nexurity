#!/usr/bin/env python3
"""Copy evidence into the engagement folder and fingerprint it, before any analysis.

    preserve_evidence.py --dest <engagement>/evidence PATH...
    preserve_evidence.py --dest <engagement>/evidence --ssh user@host /var/log/nginx /var/www/site

Sources are only read: local files are copied with their timestamps, remote files are
streamed over SSH with `cat` or `tar -c` (read-only). Each file's SHA-256 is appended
to `<dest>/SHA-256SUMS`. Python standard library only.
"""
import argparse
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def target_path(dest, source):
    relative = source.lstrip("/\\").replace("..", "_")
    return os.path.join(dest, relative)


def copy_local(source, dest):
    copied = []
    if os.path.isdir(source):
        for root, _dirs, files in os.walk(source):
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path):
                    continue
                out = target_path(dest, path)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copy2(path, out)
                copied.append((path, out))
    elif os.path.isfile(source):
        out = target_path(dest, source)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copy2(source, out)
        copied.append((source, out))
    else:
        raise FileNotFoundError(source)
    return copied


def copy_remote(host, source, dest):
    """Stream a remote file or folder with tar -c (read-only), extracting only inside dest."""
    command = ["ssh", "-o", "BatchMode=yes", host, "tar -cf - -- %s 2>/dev/null" % shlex.quote(source)]
    result = subprocess.run(command, capture_output=True)
    if result.returncode not in (0, 1) or not result.stdout:
        raise RuntimeError("could not read %s:%s (%s)" % (host, source, result.stderr.decode(errors="replace").strip()[:200]))
    copied = []
    base = os.path.join(dest, host.replace("@", "_").replace(":", "_"))
    with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            out = os.path.realpath(target_path(base, member.name))
            if not out.startswith(os.path.realpath(base) + os.sep):
                continue
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with archive.extractfile(member) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
            copied.append(("%s:/%s" % (host, member.name.lstrip("/")), out))
    return copied


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument("--dest", required=True, help="the engagement's evidence folder")
    parser.add_argument("--ssh", help="read the sources on this host over SSH")
    parser.add_argument("sources", nargs="+")
    args = parser.parse_args(argv)
    dest = os.path.abspath(args.dest)
    os.makedirs(dest, exist_ok=True)
    sums_path = os.path.join(dest, "SHA-256SUMS")
    results, errors = [], []
    for source in args.sources:
        try:
            copied = copy_remote(args.ssh, source, dest) if args.ssh else copy_local(source, dest)
        except (OSError, RuntimeError, tarfile.TarError) as exc:
            errors.append({"source": source, "error": str(exc)})
            continue
        with open(sums_path, "a", encoding="utf-8") as sums:
            for original, out in copied:
                digest = sha256(out)
                sums.write("%s  %s\n" % (digest, os.path.relpath(out, dest)))
                results.append({"source": original, "copy": out, "sha256": digest, "bytes": os.path.getsize(out)})
    print(json.dumps({"preserved": results, "errors": errors, "sums": sums_path}, indent=2))
    return 1 if errors and not results else 0


if __name__ == "__main__":
    sys.exit(main())

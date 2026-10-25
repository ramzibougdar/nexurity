#!/usr/bin/env python3
"""Create, find, log and close Nexurity engagements.

    engagement.py start   --data D --session S --cwd C --kind audit|incident --target T [--lang en|fr] [--config FILE]
    engagement.py log     --data D --ref REF --message TEXT
    engagement.py resolve --data D --ref REF
    engagement.py close   --data D (--ref REF | --session S)
    engagement.py list    --data D

The report language is the Claude Code `language` setting when it is English or French, else
`--lang` (the language of the conversation), else English.

Engagement folders live in `<cwd>/.nexurity/<REF>/`; the index and the one-file-per-session
records live in `<data>/engagements/`.
"""
import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

GITIGNORE = "# Nexurity reports and evidence: never commit them.\n*\n"


def _index_path(data):
    return os.path.join(common.engagements_dir(data), "index.json")


def _load_index(data):
    return common.read_json(_index_path(data), {}) or {}


def _next_ref(data, kind):
    config = common.load_config(data)
    prefix = config["prefixes"].get(kind, "AUD" if kind == "audit" else "INC")
    year = str(datetime.date.today().year)
    key = "%s-%s" % (prefix, year)
    counter = int(config.get("counters", {}).get(key, 0)) + 1
    config.setdefault("counters", {})[key] = counter
    common.save_config(data, config)
    return "%s-%s-%03d" % (prefix, year, counter), config


def _active_for_session(data, session):
    if not session or "${" in session:
        return None
    return common.read_json(common.session_file(data, session))


def cmd_start(args):
    data = common.data_dir(args.data)
    existing = _active_for_session(data, args.session)
    if existing:
        print(json.dumps({"error": "engagement already open in this session",
                          "ref": existing["ref"],
                          "hint": "close it first with /nexurity:audit --close %s" % existing["ref"]}))
        return 2
    cwd = os.path.abspath(os.path.expanduser(args.cwd))
    ref, _ = _next_ref(data, args.kind)
    root = os.path.join(cwd, ".nexurity")
    folder = os.path.join(root, ref)
    os.makedirs(os.path.join(folder, "evidence"), exist_ok=True)
    os.makedirs(os.path.join(folder, "tools"), exist_ok=True)
    gitignore = os.path.join(root, ".gitignore")
    if not os.path.exists(gitignore):
        with open(gitignore, "w", encoding="utf-8") as fh:
            fh.write(GITIGNORE)

    if args.config:
        audit_config = common.read_json(args.config, {}) or {}
    else:
        audit_config = {}
    language = (common.claude_code_language(cwd) or common.report_language(audit_config.get("language"))
                or args.lang or "en")
    audit_config.update({
        "ref": ref,
        "kind": args.kind,
        "target": args.target,
        "language": language,
        "created": common.now_iso(),
    })
    common.write_json(os.path.join(folder, "audit-config.json"), audit_config)
    with open(os.path.join(folder, "log.md"), "w", encoding="utf-8") as fh:
        fh.write("# %s · engagement log\n\n" % ref)
        fh.write("- %s · engagement created (target: %s)\n" % (common.now_iso(), args.target))

    record = {
        "ref": ref,
        "kind": args.kind,
        "target": os.path.abspath(os.path.expanduser(args.target)) if os.path.exists(os.path.expanduser(args.target)) else args.target,
        "folder": folder,
        "cwd": cwd,
        "session_id": args.session,
        "started": common.now_iso(),
    }
    if args.session and "${" not in args.session:
        common.write_json(common.session_file(data, args.session), record)
    else:
        record["session_id"] = None
        common.write_json(os.path.join(common.sessions_dir(data), "pending-%s.json" % ref), record)

    index = _load_index(data)
    index[ref] = {"folder": folder, "kind": args.kind, "target": args.target, "created": record["started"]}
    common.write_json(_index_path(data), index)
    print(json.dumps({"ref": ref, "folder": folder, "language": language}))
    return 0


def _folder_for(data, ref):
    entry = _load_index(data).get(ref)
    return entry["folder"] if entry else None


def cmd_log(args):
    data = common.data_dir(args.data)
    folder = _folder_for(data, args.ref)
    if not folder:
        print("unknown engagement %s" % args.ref, file=sys.stderr)
        return 1
    with open(os.path.join(folder, "log.md"), "a", encoding="utf-8") as fh:
        fh.write("- %s · %s\n" % (common.now_iso(), " ".join(args.message.split())))
    return 0


def cmd_resolve(args):
    data = common.data_dir(args.data)
    folder = _folder_for(data, args.ref)
    if not folder:
        print("unknown engagement %s" % args.ref, file=sys.stderr)
        return 1
    print(folder)
    return 0


def cmd_close(args):
    data = common.data_dir(args.data)
    folder = common.sessions_dir(data)
    removed = []
    try:
        names = os.listdir(folder)
    except OSError:
        names = []
    for name in names:
        path = os.path.join(folder, name)
        record = common.read_json(path) or {}
        by_session = args.session and name == os.path.basename(common.session_file(data, args.session))
        by_ref = args.ref and record.get("ref") == args.ref
        if by_session or by_ref:
            os.unlink(path)
            removed.append(record.get("ref"))
    if removed and args.ref:
        engagement_folder = _folder_for(data, args.ref)
        if engagement_folder and os.path.isdir(engagement_folder):
            with open(os.path.join(engagement_folder, "log.md"), "a", encoding="utf-8") as fh:
                fh.write("- %s · engagement closed\n" % common.now_iso())
    print(json.dumps({"closed": removed}))
    return 0


def cmd_list(args):
    data = common.data_dir(args.data)
    index = _load_index(data)
    active = set()
    try:
        for name in os.listdir(common.sessions_dir(data)):
            record = common.read_json(os.path.join(common.sessions_dir(data), name)) or {}
            if record.get("ref"):
                active.add(record["ref"])
    except OSError:
        pass
    rows = [{"ref": ref, "active": ref in active, **entry} for ref, entry in sorted(index.items())]
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("start")
    p.add_argument("--data")
    p.add_argument("--session", default="")
    p.add_argument("--cwd", default=os.getcwd())
    p.add_argument("--kind", choices=["audit", "incident"], required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--lang", choices=["en", "fr"], help="language of the conversation")
    p.add_argument("--config", help="audit-config.json written by the wizard")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("log")
    p.add_argument("--data")
    p.add_argument("--ref", required=True)
    p.add_argument("--message", required=True)
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("resolve")
    p.add_argument("--data")
    p.add_argument("--ref", required=True)
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser("close")
    p.add_argument("--data")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--ref")
    group.add_argument("--session")
    p.set_defaults(func=cmd_close)

    p = sub.add_parser("list")
    p.add_argument("--data")
    p.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

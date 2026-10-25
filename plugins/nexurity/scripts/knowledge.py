#!/usr/bin/env python3
"""Knowledge ledger: how an engagement used the eleven security sources shipped with Nexurity.

    knowledge.py sources                                     the eleven sources (id, name, url, applies to)
    knowledge.py ledger --data D --folder F [--target T]     write F/knowledge.json and print it

For each source the ledger says `used` (by which agents or tools), `not_applicable` (why) or `not_run`
(why). It reads only the engagement folder (audit-config.json, recon.json, candidates-*.json,
verdicts-*.json, tools/) and, to detect what applies, the names of the target's files. The report shows it
(render_report.py). Python standard library only.
"""
import argparse
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import tools  # noqa: E402

SOURCES = [
    {"id": "cloudflare-security-audit", "name": "cloudflare/security-audit-skill",
     "url": "https://github.com/cloudflare/security-audit-skill", "aliases": ["CF"], "applies": "always"},
    {"id": "cloudflare-skills", "name": "cloudflare/skills", "url": "https://github.com/cloudflare/skills",
     "aliases": ["WAF", "WBP"], "applies": "cloudflare"},
    {"id": "semgrep", "name": "semgrep/semgrep", "url": "https://github.com/semgrep/semgrep",
     "tool": "semgrep", "outputs": ["tools/semgrep*.json", "tools/semgrep*.sarif"], "applies": "code"},
    {"id": "nud3l-gist", "name": "nud3l code-audit gist", "url": "https://gist.github.com/nud3l/15468abc5c4ca7e4e0e38e5b120a7997",
     "aliases": ["nud3l-gist"], "agents": ["hunter-hygiene"], "applies": "code"},
    {"id": "solana-auditor", "name": "sanbir/solana-auditor-skills", "url": "https://github.com/sanbir/solana-auditor-skills",
     "aliases": ["SOL"], "applies": "solana"},
    {"id": "secskills-core", "name": "trilwu/secskills (secskills-core)", "url": "https://github.com/trilwu/secskills",
     "aliases": ["SK"], "applies": "code"},
    {"id": "voltagent-subagents", "name": "VoltAgent/awesome-claude-code-subagents",
     "url": "https://github.com/VoltAgent/awesome-claude-code-subagents", "aliases": ["VA"], "applies": "code"},
    {"id": "netresearch-security-audit", "name": "netresearch/security-audit-skill",
     "url": "https://github.com/netresearch/security-audit-skill", "aliases": ["NR"], "applies": "always"},
    {"id": "codeql", "name": "github/codeql", "url": "https://github.com/github/codeql",
     "tool": "codeql", "outputs": ["tools/codeql*.sarif"], "exclude": ["codeql-php"], "applies": "codeql"},
    {"id": "codeql-php", "name": "Vozec/codeql-php", "url": "https://github.com/Vozec/codeql-php",
     "tool": "codeql-php", "outputs": ["tools/codeql-php*.sarif"], "applies": "php"},
    {"id": "claude-code-security-review", "name": "anthropics/claude-code-security-review",
     "url": "https://github.com/anthropics/claude-code-security-review", "aliases": ["CCSR"], "applies": "always"},
]
SKIP_DIRS = {".git", ".nexurity", "node_modules", "vendor", ".venv", "venv", "dist", "build", "__pycache__"}
CODEQL_EXT = {".js": "javascript-typescript", ".jsx": "javascript-typescript", ".mjs": "javascript-typescript",
              ".cjs": "javascript-typescript", ".ts": "javascript-typescript", ".tsx": "javascript-typescript",
              ".py": "python", ".rb": "ruby", ".java": "java-kotlin", ".kt": "java-kotlin", ".cs": "csharp"}
MAX_FILES = 50000


def scan_target(target):
    """What the target contains, from file names only."""
    found = {"wrangler": False, "solana": False, "codeql": set(), "php": False, "files": 0}
    if not target or not os.path.isdir(target):
        return found
    for dirpath, dirnames, names in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in names:
            found["files"] += 1
            if name in ("wrangler.toml", "wrangler.json", "wrangler.jsonc"):
                found["wrangler"] = True
            if name == "Anchor.toml" or name == "Xargo.toml":
                found["solana"] = True
            ext = os.path.splitext(name)[1].lower()
            if ext in (".php", ".phtml", ".inc"):
                found["php"] = True
            if ext in CODEQL_EXT:
                found["codeql"].add(CODEQL_EXT[ext])
            if ext in (".yml", ".yaml") and dirpath.replace(os.sep, "/").endswith(".github/workflows"):
                found["codeql"].add("actions")
        if found["files"] > MAX_FILES:
            break
    return found


def reports(folder):
    """{agent: [checklists used]} from the agents' saved answers."""
    used = {}
    for path in sorted(glob.glob(os.path.join(folder, "candidates-*.json")) +
                       glob.glob(os.path.join(folder, "verdicts-*.json")) + [os.path.join(folder, "recon.json")]):
        data = common.read_json(path)
        if not isinstance(data, dict):
            continue
        base = os.path.basename(path)[:-5]
        agent = "recon" if base == "recon" else ("verifier" if base.startswith("verdicts-") else base[len("candidates-"):])
        items = (data.get("coverage") or {}).get("checklists_used") or data.get("checklists_used") or []
        used.setdefault(agent, []).extend(str(i) for i in items if isinstance(i, str))
    return used


def ledger(data, folder, target=None):
    config = common.read_json(os.path.join(folder, "audit-config.json"), {}) or {}
    recon = common.read_json(os.path.join(folder, "recon.json"), {}) or {}
    target = target or config.get("target")
    scan = scan_target(target)
    recon_text = json.dumps(recon).lower()
    kind = config.get("type") or ("code" if scan["files"] else "")
    has_code = kind in ("code", "several") or (not kind and scan["files"] > 0)
    solana = scan["solana"] or bool(re.search(r"\b(solana|anchor-lang|anchor)\b", recon_text))
    cloudflare = scan["wrangler"] or "wrangler" in recon_text
    agents = reports(folder)
    rows = []
    for source in SOURCES:
        row = {"id": source["id"], "name": source["name"], "url": source["url"], "used_by": []}
        for agent, items in sorted(agents.items()):
            if any(item.split(" ", 1)[0] in source.get("aliases", []) or item == source["id"] for item in items):
                row["used_by"].append(agent)
        for agent in source.get("agents", []):
            if agent in agents and agent not in row["used_by"]:
                row["used_by"].append(agent)
        outputs = [f for p in source.get("outputs", []) for f in glob.glob(os.path.join(folder, p))
                   if not any(x in os.path.basename(f) for x in source.get("exclude", []))]
        if source.get("tool") and outputs:
            row["used_by"].append(source["tool"])
        applies = source["applies"]
        if row["used_by"]:
            row["status"] = "used"
        elif applies in ("code", "solana", "codeql", "cloudflare", "php") and not has_code:
            row.update(status="not_applicable", reason="no_code")
        elif applies == "solana" and not solana:
            row.update(status="not_applicable", reason="no_solana")
        elif applies == "cloudflare" and not cloudflare:
            row.update(status="not_applicable", reason="no_cloudflare")
        elif applies == "codeql" and not scan["codeql"]:
            row.update(status="not_applicable", reason="no_codeql_language")
        elif applies == "php" and not (scan["php"] or re.search(r"\bphp\b", recon_text)):
            row.update(status="not_applicable", reason="no_php")
        elif source.get("tool") and not tools.find(source["tool"], data):
            row.update(status="not_run", reason="not_installed")
        elif source.get("tool"):
            row.update(status="not_run", reason="no_output")
        else:
            row.update(status="not_run", reason="not_reported")
        rows.append(row)
    return {"generated": common.now_iso(), "audit_type": kind or None,
            "codeql_languages": sorted(scan["codeql"]), "sources": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("sources", allow_abbrev=False)
    p = sub.add_parser("ledger", allow_abbrev=False)
    p.add_argument("--data")
    p.add_argument("--folder", required=True, help="the engagement folder")
    p.add_argument("--target", help="the audited folder (default: the target in audit-config.json)")
    args = parser.parse_args(argv)
    if args.command == "sources":
        print(json.dumps([{k: s[k] for k in ("id", "name", "url", "applies")} for s in SOURCES], indent=2))
        return 0
    result = ledger(common.data_dir(args.data), os.path.abspath(args.folder), args.target)
    common.write_json(os.path.join(os.path.abspath(args.folder), "knowledge.json"), result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

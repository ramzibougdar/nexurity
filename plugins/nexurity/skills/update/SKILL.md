---
name: update
description: Checks for new versions of Nexurity, its ported CVSS calculator and the audit tools, and guides the updates. Never updates silently.
disable-model-invocation: true
---

# Nexurity · updates

Paths for this run:
- plugin: `${CLAUDE_PLUGIN_ROOT}`
- data: `${CLAUDE_PLUGIN_DATA}`
- session id: `${CLAUDE_SESSION_ID}`
- arguments: `$ARGUMENTS`

Before anything else, read `${CLAUDE_PLUGIN_ROOT}/reference/RULES.md` and follow it for the whole run.

1. Run a full check: `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/check_updates.py" --data "${CLAUDE_PLUGIN_DATA}" --full --json`.
2. Show each item with a new version: current → new, and what it affects.
3. **Nexurity itself**: it is updated through Claude Code, never by editing the plugin files. Tell the user to
   run `claude plugin update nexurity@nexurity-marketplace` (or `/plugin`, Marketplaces tab) and to start a new
   session afterwards.
4. **Ported source** (FIRST CVSS calculator): show the upstream changes (`git ls-remote` / the repository's
   history) and explain that porting them is the plugin maintainer's job; nothing is copied automatically.
5. **Tools** (semgrep, gitleaks…): show the update command of each tool's own installer and run it only after
   the user approves that exact command. Never use `sudo` without asking.
6. Items "not checked" (offline, GitHub quota): say so, with the reset time when given. If the quota is the
   problem, explain that exporting a `GITHUB_TOKEN` with no permission before starting Claude Code raises the
   limit to 5,000 requests per hour.

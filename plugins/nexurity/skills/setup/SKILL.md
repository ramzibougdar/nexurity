---
name: setup
description: Installs the audit tools Nexurity uses (semgrep, CodeQL, pip-audit, gitleaks, trufflehog, lynis, testssl.sh, and cargo-audit when Rust is installed), without sudo and without asking.
argument-hint: "[--upgrade]"
disable-model-invocation: true
---

# Nexurity · tool setup

Paths for this run:
- plugin: `${CLAUDE_PLUGIN_ROOT}`
- data: `${CLAUDE_PLUGIN_DATA}`
- session id: `${CLAUDE_SESSION_ID}`
- arguments: `$ARGUMENTS`

Before anything else, read `${CLAUDE_PLUGIN_ROOT}/reference/RULES.md` and follow it for the whole run.

1. Tell the user in one line that the installation starts and can take a few minutes. Do not ask anything.
2. Run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/tools.py" install --data "${CLAUDE_PLUGIN_DATA}"`, adding
   `--upgrade` when the arguments contain it. Give the command a 30-minute timeout (or run it in the
   background and wait for it): it installs with Homebrew when present, otherwise in Nexurity's data folder
   (private Python environment, official GitHub releases checked by SHA-256, official repositories).
3. Show the result as a table: tool, status (present, installed, updated, skipped, failed), how, and the
   reason for anything skipped or failed. For a failure, give the tool's own install command as the
   alternative (for example `brew install <formula>` or the tool's documentation link) without running it.
4. CodeQL is installed from the official CodeQL bundle (about 700 MB to 1.3 GB to download, 3 GB on disk).
   Remind the user once that CodeQL is free for open-source code and needs a GitHub Advanced Security
   licence for closed-source code.
5. Never use `sudo`, never install anything else, and never run this while an engagement is open (the
   safeguard refuses it: close the engagement first).

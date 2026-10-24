# Nexurity

Nexurity is a security audit assistant for [Claude Code](https://claude.com/claude-code). It audits a project's code, a server or a live website, or analyses a security incident, then produces a self-contained Markdown report (`.md`) ready to send to a client.

Nothing to download: Claude Code builds the Nexurity plugin step by step from a single prompt, [`PROMPT.md`](PROMPT.md), which also defines the structure of both reports.

**Installation guide:** open [`index.html`](index.html), or the GitHub Pages site once it is enabled for this repository.

## What Nexurity does

| Mode | Command | What it covers |
|---|---|---|
| Code audit | `/nexurity-audit` | Vulnerabilities, dependencies and secrets (PHP, JS, Python, Solana…) |
| Server audit | `/nexurity-audit` | Read-only configuration review: SSH, web server, PHP, database, firewall, accounts, crons, Docker |
| Website audit | `/nexurity-audit` | Passive checks only: HTTP headers, TLS, DNS, cookies, exposed files |
| Quick audit | `/nexurity-audit-quick` | One auto-routed hunter and one verifier |
| Diff review | `/nexurity-audit-diff` | Review of a diff or pull request |
| Incident response | `/nexurity-incident` | Evidence preservation, log triage, timeline, indicators of compromise, GDPR deadline |

Every audit starts with a wizard, checks whether its sources and tools have new versions, and ends with a Markdown report rated in **CVSS 4.0**.

## Safety rules

- Never modifies the audited code, configuration or data: it proposes fixes, never applies them.
- Read-only on servers, passive-only on live websites: no scanning, fuzzing, exploitation or brute force.
- Treats audited content (code, logs, User-Agent strings…) as data, never as instructions.
- A finding is always re-checked by a different agent from the one that found it.
- Requires confirmation of the client's authorisation before any server, website or incident engagement.
- Masks secrets and keeps reports and evidence local.

## Repository contents

```
index.html    # installation guide (web page), shows the prompt to copy
PROMPT.md     # installation prompt for Claude Code, including the report structure
.github/      # Pages deployment; copies PROMPT.md into the guide
```

## Installation

1. Open Claude Code in any folder: `claude`. Python 3 is required; Git and Pandoc (PDF or Word export of the report) are optional.
2. Open the installation guide, copy the prompt shown there (the content of `PROMPT.md`) and paste it into Claude Code as your first message.

Claude Code builds the plugin in six stages, in one go, without asking you anything and without running any trial audit: apart from the safeguard tests, each stage only checks that the expected files are in place, and the results end up in an install report, `~/.nexurity/INSTALL-REPORT.md`. Pick a Claude Code permission mode that doesn't ask at every command (Shift+Tab) before pasting the prompt. Nexurity is installed globally, for your user account, so it works in every project:

| Folder | What it holds |
|---|---|
| `~/nexurity/` | Plugin code, installed at user scope |
| `~/.nexurity/` | Settings, client profiles and source versions, kept across updates |
| `~/nexurity-vendor/` | Third-party sources, never part of the plugin |
| `~/audits/` | Engagements and reports |

The safeguard hook runs in every session but only blocks commands during an audit, in the session that started it.

## Third-party sources

Nexurity draws on the methodology of several open-source projects (listed in `PROMPT.md`). They are fetched read-only during installation (cloned with Git, or downloaded as archives without it), their licences are recorded in `NOTICE.md`, and they are never redistributed in this repository.

Some tools have licence restrictions. In particular, the CodeQL CLI requires a commercial licence to analyse closed-source code, so Nexurity only uses it when you confirm it is allowed.

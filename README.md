# Nexurity

Nexurity is a security audit assistant for [Claude Code](https://claude.com/claude-code). It audits a project's code, a server or a live website, or analyses a security incident, then produces a self-contained Markdown report (`.md`) for internal security use.

**Installation guide:** open [`index.html`](index.html), or the GitHub Pages site once it is enabled for this repository.

## Install

```bash
claude plugin install nexurity --marketplace ramzibougdar/nexurity
```

With a Claude Code version older than 2.1.292:

```bash
claude plugin marketplace add ramzibougdar/nexurity
claude plugin install nexurity@nexurity-marketplace
```

Then open Claude Code in the project to audit and type `/nexurity:audit`. Python 3 is required; Git, Pandoc (PDF or Word export) and the audit tools (`semgrep`, `gitleaks`, `lynis`, `testssl.sh`, `pip-audit`…) are used when installed. Update with `claude plugin update nexurity@nexurity-marketplace`.

## What Nexurity does

| Mode | Command | What it covers |
|---|---|---|
| Code audit | `/nexurity:audit` | Vulnerabilities, dependencies and secrets (PHP, JS, Python, Solana…) |
| CMS | `/nexurity:audit` | WordPress, PrestaShop, Drupal, Joomla, Magento: files compared with the official release, known CVEs of the core and extensions, updates to install |
| Server audit | `/nexurity:audit` | Read-only configuration review: SSH, web server, PHP, database, firewall, accounts, crons, Docker |
| Website audit | `/nexurity:audit` | Passive checks only: HTTP headers, TLS, DNS, cookies, exposed files; local sites (`localhost`, `*.test`…) too |
| Quick audit | `/nexurity:audit-quick` | One auto-routed hunter and one verifier |
| Diff review | `/nexurity:audit-diff` | Review of a diff or pull request |
| Incident response | `/nexurity:incident` | Evidence preservation, log triage, timeline, indicators of compromise, GDPR deadline |
| Report | `/nexurity:report <REF>` | Regenerates a report from its JSON, with optional PDF or Word export |
| Updates | `/nexurity:update` | New versions of Nexurity and of the audit tools |

Every audit asks only what it cannot detect (type, goal, target), always covers every area in depth, checks whether Nexurity and the tools have new versions, and ends with a Markdown report rated in **CVSS 4.0**. Reports and evidence go to `./.nexurity/<REF>/` in the folder where you started Claude Code; that folder ignores itself in Git.

## Safety rules

- Never modifies the audited code, configuration or data: it proposes fixes, never applies them.
- Read-only on servers, passive-only on websites: no scanning, fuzzing, exploitation or brute force. A hook enforces it during an audit, in the session that started it.
- Treats audited content (code, logs, User-Agent strings…) as data, never as instructions.
- A finding is always re-checked by a different agent from the one that found it; CVSS scores are computed by a script, never written by the model.
- Internal use: audit your own systems, or systems you are authorised to audit. It starts without a confirmation question.
- Masks secrets and keeps reports and evidence local.

## Repository contents

```
.claude-plugin/marketplace.json   # the marketplace: lists the plugin
plugins/nexurity/                 # the plugin (skills, agents, hook, scripts, tests)
PROMPT.md                         # the specification the plugin follows; can also build it from scratch
index.html                        # installation guide (web page)
.github/                          # Pages deployment and plugin tests
```

To build your own variant instead of installing the plugin, paste `PROMPT.md` into Claude Code (see the guide, "Build it from the prompt").

## Development

```bash
python3 -m unittest discover -s plugins/nexurity/tests
claude plugin validate --strict ./plugins/nexurity
claude plugin validate .
```

## Third-party code

`plugins/nexurity/scripts/cvss4.py` is a Python port of the FIRST CVSS v4.0 calculator (BSD-2-Clause). Other projects inspired the methodology but nothing was copied from them. Details and licences: [`plugins/nexurity/NOTICE.md`](plugins/nexurity/NOTICE.md).

Some tools have licence restrictions. In particular, the CodeQL CLI requires a commercial licence to analyse closed-source code, so Nexurity only uses it when you confirm it is allowed.

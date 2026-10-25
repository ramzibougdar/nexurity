# Nexurity

Security audit assistant for Claude Code. It audits a project's code, a server or a live website
(passively), or analyses a security incident, then writes a Markdown report rated in CVSS 4.0.

## Install

```bash
claude plugin install nexurity --marketplace ramzibougdar/nexurity
```

With Claude Code older than 2.1.292, in two steps:

```bash
claude plugin marketplace add ramzibougdar/nexurity
claude plugin install nexurity@nexurity-marketplace
```

The plugin is installed for your user account and works in every project. Only Python 3 is required.
Audit tools are used when installed (`semgrep`, `gitleaks` or `trufflehog`, `lynis`, `testssl.sh`,
`composer`, `npm`, `pip-audit`, `cargo-audit`); `pandoc` exports reports to PDF or Word. Nexurity
never installs a tool by itself.

Update with `claude plugin update nexurity@nexurity-marketplace`, then start a new session.

## CMS

When the audited project is a CMS (WordPress, PrestaShop, Drupal, Joomla, Magento), Nexurity detects it,
its version and its extensions, then `scripts/cms.py`:
- compares every file with the official release of the same version (WordPress.org checksums, official
  release archives) and writes a diff of each modified file: injected code and web shells stand out;
- lists the known CVEs of the core and of each plugin, module or theme (NVD, OSV.dev, and WPScan when
  `WPSCAN_API_TOKEN` is set), with the version that fixes each one;
- lists the updates to install (latest version, latest in the installed branch, security releases).

The `hunter-cms` agent checks which CVEs really apply and reads the diffs. Only names and versions are sent
to these sources. Set `NVD_API_KEY` to speed up the NVD lookups.

## Commands

| Command | What it does |
|---|---|
| `/nexurity:audit` | Full audit of code, a server or a live website, with two short screens (type and goal, then target) |
| `/nexurity:audit-quick` | One hunter chosen automatically and one verifier |
| `/nexurity:audit-diff` | Review of a diff, a branch or a pull request |
| `/nexurity:incident` | Incident response: evidence, log triage, timeline, IOCs, GDPR deadline |
| `/nexurity:report <REF>` | Regenerates a report from its JSON (`--pdf`, `--docx` with Pandoc) |
| `/nexurity:update` | Checks for new versions of Nexurity and the tools |
| `/nexurity:audit --close <REF>` | Closes an engagement left open by an interrupted session |
| `/nexurity:audit --list` | Lists the engagements |

## Where things go

| Folder | What it holds |
|---|---|
| `./.nexurity/<REF>/` | Each engagement, in the folder where you started Claude Code: `audit-config.json`, `evidence/`, `findings.json` or `incident.json`, `report.md`, `log.md`. The folder ignores itself in Git. |
| `${CLAUDE_PLUGIN_DATA}` (`~/.claude/plugins/data/…`) | Settings (`config.json`), engagement index, cached CMS release archives (`cms-baselines/`), update-check cache. Deleted if you uninstall the plugin. |

## Safety

- Read-only on the target: fixes are proposed, never applied.
- A `PreToolUse` hook enforces it during an engagement, in the session that started it only: an
  allowlist of read-only commands (locally and over SSH), writes only inside the engagement folder.
  Outside an engagement it allows everything.
- Websites are audited passively, including local ones (`localhost`, `*.test`, `*.local`…).
- Audited content is data, never instructions; prompt-injection attempts are reported as indicators.
- Every finding is re-checked by a different agent; CVSS 4.0 scores are computed by
  `scripts/cvss4.py` (port of the FIRST calculator), never written by the model.
- Secrets are masked (first and last 4 characters). Reports and evidence stay on your machine; the
  audited material is processed by the Claude model.

## Development

```bash
python3 -m unittest discover -s plugins/nexurity/tests
claude plugin validate --strict ./plugins/nexurity
claude plugin validate .
```

Third-party code and references: see `NOTICE.md`. The specification the plugin follows is `PROMPT.md`
at the root of the repository.

# Nexurity

Nexurity is a security audit assistant for [Claude Code](https://claude.com/claude-code). It audits a project's code, a server or a live website, or analyses a security incident, then produces a self-contained HTML report ready to send to a client.

This repository is the **installation kit**: Claude Code builds the Nexurity plugin step by step from `PROMPT.md`.

## What Nexurity does

| Mode | Command | What it covers |
|---|---|---|
| Code audit | `/audit` | Vulnerabilities, dependencies and secrets (PHP, JS, Python, Solana…) |
| Server audit | `/audit` | Read-only configuration review: SSH, web server, PHP, database, firewall, accounts, crons, Docker |
| Website audit | `/audit` | Passive checks only: HTTP headers, TLS, DNS, cookies, exposed files |
| Quick audit | `/audit-quick` | One auto-routed hunter and one verifier |
| Diff review | `/audit-diff` | Review of a diff or pull request |
| Incident response | `/incident` | Evidence preservation, log triage, timeline, indicators of compromise, GDPR deadline |

Every audit starts with a wizard, checks whether its sources and tools have new versions, and ends with an HTML report rated in **CVSS 4.0**.

## Safety rules

- Never modifies the audited code, configuration or data: it proposes fixes, never applies them.
- Read-only on servers, passive-only on live websites: no scanning, fuzzing, exploitation or brute force.
- Treats audited content (code, logs, User-Agent strings…) as data, never as instructions.
- A finding is always re-checked by a different agent from the one that found it.
- Requires confirmation of the client's authorisation before any server, website or incident engagement.
- Masks secrets and keeps reports and evidence local.

## Repository contents

```
PROMPT.md                              # installation prompt for Claude Code
base/
├── security-audit-template.html       # generic audit report template
└── incident-report-template.html      # generic incident report template
```

The two templates are generic and carry the Nexurity identity by default. During installation, `/nexurity-setup` asks for the issuing company's name, logo, colours, fonts and contact details, then **creates the branded HTML documents** from these base templates.

## Installation

1. Clone this repository and open Claude Code in it:
   ```bash
   git clone https://github.com/ramzibougdar/nexurity.git
   cd nexurity
   claude
   ```
2. If the reports must carry another company's identity, have its name, SVG logo, colours, fonts and contact details ready.
3. In Claude Code, type: `Read PROMPT.md and follow it`.

Claude Code builds the plugin in eight stages and waits for your approval at the end of each one.

## Third-party sources

Nexurity draws on the methodology of several open-source projects (listed in `PROMPT.md`). They are cloned read-only during installation, their licences are recorded in `NOTICE.md`, and they are never redistributed in this repository.

Some tools have licence restrictions. In particular, the CodeQL CLI requires a commercial licence to analyse closed-source code, so Nexurity only uses it when you confirm it is allowed.

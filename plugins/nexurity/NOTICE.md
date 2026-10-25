# Notice

Nexurity is written for this plugin. It includes code ported from one third-party project, and it takes
ideas (never text or code) from a few others. Versions are pinned in `sources.lock.json`.

## Code ported

### FIRST CVSS v4.0 calculator

- Source: https://github.com/FIRSTdotorg/cvss-v4-calculator (commit `c5b0d409ae9f57c44264c6ce5f27d89298e1d32a`)
- Used in: `scripts/cvss4.py`, a Python port of `cvss_score.js`, `cvss_lookup.js`, `max_composed.js`,
  `max_severity.js` and `metrics.js` (scoring algorithm and lookup tables). The port gives the same score
  as the reference on all 104,976 base vectors and on 30,000 random vectors with threat and
  environmental metrics.
- Licence: BSD-2-Clause, reproduced below.

```
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.```

## Third-party skills included (unmodified)

These security skills are copied **unmodified**, at the commit shown, into `vendor/`, each with its
licence file(s). Nexurity's agents read them as checklists (`reference/KNOWLEDGE.md`); Nexurity's own rules
take precedence over their instructions. The full list of copied files is in `vendor/SOURCES.json`, and
`.github/scripts/vendor.py --check` verifies them against their sources.

| Source | Folder | Commit | Licence |
|---|---|---|---|
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | `vendor/cloudflare-security-audit/` | `c1c8a8c14710` | MIT |
| [cloudflare/skills (WAF reference and Workers best practices)](https://github.com/cloudflare/skills) | `vendor/cloudflare-skills/` | `86505e44f87d` | Apache-2.0 |
| [netresearch/security-audit-skill](https://github.com/netresearch/security-audit-skill) | `vendor/netresearch-security-audit/` | `5319ab55db58` | CC-BY-SA-4.0 (content), MIT (code, not included) |
| [trilwu/secskills (secskills-core, audit skills only)](https://github.com/trilwu/secskills) | `vendor/secskills-core/` | `ca53957bcd8e` | MIT |
| [sanbir/solana-auditor-skills](https://github.com/sanbir/solana-auditor-skills) | `vendor/solana-auditor/` | `e501915ff495` | MIT |
| [VoltAgent/awesome-claude-code-subagents (security and code review agents)](https://github.com/VoltAgent/awesome-claude-code-subagents) | `vendor/voltagent-subagents/` | `408d3c9eee2d` | MIT |
| [anthropics/claude-code-security-review (review prompt and false-positive rules)](https://github.com/anthropics/claude-code-security-review) | `vendor/claude-code-security-review/` | `0c6a49f1fa56` | MIT |

- **netresearch/security-audit-skill**: content by Netresearch DTT GmbH, licensed under CC BY-SA 4.0
  (https://creativecommons.org/licenses/by-sa/4.0/); included unmodified. Only its content files (skill
  definition, references, checkpoints) are included, none of its scripts.
- **cloudflare/skills**: Copyright Cloudflare, Inc., Apache License 2.0; only the WAF reference
  (`skills/cloudflare/references/waf/`) and the Workers best practices (`skills/workers-best-practices/`)
  are included, unmodified; the other skills are product guides for building on Cloudflare, not audits.
- **anthropics/claude-code-security-review**: two files of its Python package (`prompts.py`,
  `findings_filter.py`) are included as reading material for the verifier and the diff review; they are
  never executed.
- Not included: secskills `secskills-offense` and the binary-reversing skills of `secskills-core`,
  VoltAgent's other agents (including `penetration-tester`), and every script, validator or hook of these
  projects.

## Cited only (not copied)

| Project | Why |
|---|---|
| https://gist.github.com/nud3l/15468abc5c4ca7e4e0e38e5b120a7997 | no licence: not copied; its method (parallel audit agents launched in one message, hygiene review) is applied in PIPELINE.md and by `agents/hunter-hygiene.md`, written from scratch |
| https://github.com/semgrep/semgrep | a tool, not a skill: installed by /nexurity:setup and run by the main thread (TOOLS.md) |
| https://github.com/github/codeql | a tool, not a skill: installed by /nexurity:setup (official CodeQL bundle) and run on every full code audit (TOOLS.md) |

## Standards referenced

OWASP Top 10 (2021), OWASP ASVS 4.0, CWE Top 25, CVSS 4.0 (FIRST), ANSSI guidelines, GDPR articles 33
and 34. Names and identifiers only.

## Data sources queried by the CMS check

`scripts/cms.py` queries, at audit time, only with the CMS and extension names and versions: the
WordPress.org APIs (core and plugin checksums, versions), the official release archives (GitHub releases of
PrestaShop and Joomla, ftp.drupal.org), updates.drupal.org, OSV.dev (advisories from the GitHub Advisory
Database, CC-BY 4.0), and WPScan when the user sets `WPSCAN_API_TOKEN` (the free WPScan plan is limited to
non-commercial use: check its terms for your use). This product uses the NVD API but is not endorsed or
certified by the NVD. Nothing from these sources is shipped with Nexurity.

## Tools called, not included

Semgrep, CodeQL, Lynis, testssl.sh, gitleaks, trufflehog, composer, npm, pip-audit, cargo-audit, Pandoc
are run on the user's machine; none is shipped with Nexurity (`/nexurity:setup` downloads the missing
ones from their official sources). CodeQL's terms make it free for open-source code and research;
analysing closed-source code requires a GitHub Advanced Security licence, which is the user's
responsibility.

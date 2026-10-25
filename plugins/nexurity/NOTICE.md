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

## Ideas only (nothing copied)

These projects were consulted for methodology. Nexurity's agents, rules and scripts are written from
scratch; no text or code from them is included.

| Project | What inspired Nexurity |
|---|---|
| https://github.com/cloudflare/security-audit-skill | phased audit pipeline, coverage map, adversarial validation |
| https://github.com/anthropics/claude-code-security-review | review of a diff or pull request |
| https://github.com/trilwu/secskills (`secskills-core` only) | code-audit checklists |
| https://github.com/netresearch/security-audit-skill | PHP checklist |
| https://github.com/sanbir/solana-auditor-skills | Solana checklist |

## Standards referenced

OWASP Top 10 (2021), OWASP ASVS 4.0, CWE Top 25, CVSS 4.0 (FIRST), ANSSI guidelines, GDPR articles 33
and 34. Names and identifiers only.

## Tools called, not included

Semgrep, CodeQL, Lynis, testssl.sh, gitleaks, trufflehog, composer, npm, pip-audit, cargo-audit, Pandoc
are run if they are installed on the user's machine; none is shipped with Nexurity. The CodeQL CLI
requires a commercial licence to analyse closed-source code: Nexurity only runs it when the user
confirms the code is open source or licensed.

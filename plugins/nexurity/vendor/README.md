# Third-party security skills

Security skills from other projects, copied **unmodified** at a pinned commit with their licences. Nexurity's
agents read them as checklists: `../reference/KNOWLEDGE.md` says which agent reads what, and its
"Precedence" section says what to ignore in them (their workflows, scripts, output formats and scoring).
Nothing here is ever executed.

| Folder | Source | Licence |
|---|---|---|
| `cloudflare-security-audit/` | cloudflare/security-audit-skill | MIT |
| `cloudflare-skills-waf/` | cloudflare/skills, WAF reference only | Apache-2.0 |
| `netresearch-security-audit/` | netresearch/security-audit-skill, content only | CC BY-SA 4.0 |
| `secskills-core/` | trilwu/secskills, audit skills of secskills-core only | MIT |
| `solana-auditor/` | sanbir/solana-auditor-skills | MIT |
| `voltagent-subagents/` | VoltAgent/awesome-claude-code-subagents, security-auditor and code-reviewer | MIT |
| `claude-code-security-review/` | anthropics/claude-code-security-review, review prompt and false-positive rules | MIT |

Commits, included paths and licence files: `SOURCES.json`. Attribution: `../NOTICE.md`.

## Maintenance (repository maintainers)

```bash
python3 .github/scripts/vendor.py --check    # the files match their sources at the pinned commits
python3 .github/scripts/vendor.py --update   # move every source to its latest commit
```

After `--update`, review the diff (new instructions, scripts, licence changes) before committing; a licence
change that forbids redistribution means removing that source. `/nexurity:update` tells users when an
upstream repository has new commits; they get them with the next Nexurity release.

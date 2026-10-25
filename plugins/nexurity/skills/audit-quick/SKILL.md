---
name: audit-quick
description: Quick Nexurity audit: one hunter chosen automatically and one verifier, for a fast check of code, a server or a website.
argument-hint: "[target]"
disable-model-invocation: true
---

# Nexurity · quick audit

Paths for this run:
- plugin: `${CLAUDE_PLUGIN_ROOT}`
- data: `${CLAUDE_PLUGIN_DATA}`
- session id: `${CLAUDE_SESSION_ID}`
- arguments: `$ARGUMENTS`

Before anything else, read `${CLAUDE_PLUGIN_ROOT}/reference/RULES.md` and follow it for the whole run.

Run the full audit pipeline of `${CLAUDE_PLUGIN_ROOT}/reference/PIPELINE.md` with these differences:
- no question and no confirmation: the target is the argument, or the current folder when there is none
  (language as in `${CLAUDE_PLUGIN_ROOT}/reference/WIZARD.md`);
- depth is "quick": after the recon, run the **single** hunter that `${CLAUDE_PLUGIN_ROOT}/reference/ROUTING.md`
  selects first for the main stack (`hunter-cms` after `cms.py scan` when the target is a CMS), then **one**
  verifier for all its candidates;
- no CodeQL; deterministic tools only if they take less than a minute (Semgrep with `--config auto` on the
  code, the dependency audit of the main ecosystem);
- the report is rendered as usual (`render_report.py`), and the engagement is closed at the end.

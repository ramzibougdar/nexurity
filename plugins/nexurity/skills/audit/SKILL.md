---
name: audit
description: Full Nexurity security audit of project code, a server or a live website (passive), with a wizard, independent verification and a Markdown report rated in CVSS 4.0.
argument-hint: "[--resume REF | --close REF | --config FILE | --list]"
disable-model-invocation: true
---

# Nexurity · full audit

Paths for this run:
- plugin: `${CLAUDE_PLUGIN_ROOT}`
- data: `${CLAUDE_PLUGIN_DATA}`
- session id: `${CLAUDE_SESSION_ID}`
- arguments: `$ARGUMENTS`

Before anything else, read `${CLAUDE_PLUGIN_ROOT}/reference/RULES.md` and follow it for the whole run.

## Arguments

- `--close <REF>`: run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/engagement.py" close --data "${CLAUDE_PLUGIN_DATA}" --ref <REF>`,
  report the result and stop. Use it for an engagement left open by an interrupted session.
- `--list`: run `python3 "${CLAUDE_PLUGIN_ROOT}/scripts/engagement.py" list --data "${CLAUDE_PLUGIN_DATA}"`, show the
  engagements (ref, target, folder, active or not) and stop.
- `--resume <REF>`: reload that engagement's `audit-config.json` (folder from `engagement.py resolve`), show the
  recap and run a new engagement with the same answers, without asking anything.
- `--config <file>`: non-interactive mode, no question.
- No argument: interactive audit.

## Steps

Follow `${CLAUDE_PLUGIN_ROOT}/reference/PIPELINE.md` from step 0 to step 11, with:
- the wizard of `${CLAUDE_PLUGIN_ROOT}/reference/WIZARD.md` ("/nexurity:audit");
- routing from `${CLAUDE_PLUGIN_ROOT}/reference/ROUTING.md`, tools from `${CLAUDE_PLUGIN_ROOT}/reference/TOOLS.md`,
  severity from `${CLAUDE_PLUGIN_ROOT}/reference/SEVERITY.md`, data formats from
  `${CLAUDE_PLUGIN_ROOT}/reference/REPORT.md`;
- the agents of this plugin: `recon-code`, `recon-server`, `recon-site`, the hunters chosen by routing
  (`hunter-cms` with `scripts/cms.py` for WordPress, PrestaShop, Drupal, Joomla and Magento),
  `verifier` and `report-writer`.

The engagement starts with `--kind audit`, `--session "${CLAUDE_SESSION_ID}"` and `--cwd` set to the folder
Claude Code was started in. When the type is "Several", run the recon and hunters of each part, then one
verification, one `findings.json` and one report.

Scope and depth are never asked: every area that applies to the target, and depth **thorough** (routed
hunters on the whole scope, a second pass on the sensitive areas found by the recon, and smaller
verification batches). Only the "Quick audit" goal runs as `/nexurity:audit-quick` does.

Always close the engagement at the end, including after a cancellation or an error.

---
name: incident
description: Nexurity incident response for a suspected hack: preserves evidence, triages logs, rebuilds the timeline, finds the entry point, lists indicators of compromise and the GDPR deadline.
argument-hint: "[--close REF]"
disable-model-invocation: true
---

# Nexurity · incident response

Paths for this run:
- plugin: `${CLAUDE_PLUGIN_ROOT}`
- data: `${CLAUDE_PLUGIN_DATA}`
- session id: `${CLAUDE_SESSION_ID}`
- arguments: `$ARGUMENTS`

Before anything else, read `${CLAUDE_PLUGIN_ROOT}/reference/RULES.md` and follow it for the whole run.

- `--close <REF>`: close that engagement (`engagement.py close`) and stop.

1. Update check, as in step 0 of `${CLAUDE_PLUGIN_ROOT}/reference/PIPELINE.md`.
2. Short wizard of `${CLAUDE_PLUGIN_ROOT}/reference/WIZARD.md` ("/nexurity:incident"), including the time of
   awareness (for the 72-hour GDPR notification deadline) and the authorisation confirmation.
3. Start the engagement with `--kind incident`.
4. Follow `${CLAUDE_PLUGIN_ROOT}/reference/FORENSICS.md`: preserve evidence **before any analysis**, triage the
   logs, run `forensic-logs`, `forensic-files` and `forensic-persistence` in parallel (a single message), then
   the `verifier` on every conclusion.
5. If the website is still online and compromised, tell the user at once what to contain first (take the site
   offline or block the IOCs) — as advice: Nexurity does not do it.
6. Build `<folder>/incident.json` (format in `${CLAUDE_PLUGIN_ROOT}/reference/REPORT.md`), get the plain-language
   parts from `report-writer`, render with `render_report.py` and close the engagement.
7. Remind the user of the notification deadline computed in the report, and that the decision to notify belongs
   to the data controller.

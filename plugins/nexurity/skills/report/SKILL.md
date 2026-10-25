---
name: report
description: Regenerates a Nexurity Markdown report from an engagement's findings.json or incident.json, optionally exporting it to PDF or Word with Pandoc.
argument-hint: "REF [--pdf] [--docx]"
disable-model-invocation: true
---

# Nexurity · regenerate a report

Paths for this run:
- plugin: `${CLAUDE_PLUGIN_ROOT}`
- data: `${CLAUDE_PLUGIN_DATA}`
- session id: `${CLAUDE_SESSION_ID}`
- arguments: `$ARGUMENTS`

Before anything else, read `${CLAUDE_PLUGIN_ROOT}/reference/RULES.md` and follow it for the whole run.

Run:

```
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/render_report.py" --data "${CLAUDE_PLUGIN_DATA}" --ref <REF> [--pdf] [--docx]
```

- It reads `<folder>/findings.json` or `<folder>/incident.json` and rewrites `<folder>/report.md`.
- If it refuses (invalid CVSS vector, stored score different from the computed one, unknown status), explain
  the error, fix the **JSON** with the user's agreement, and run it again. Never edit `report.md` by hand.
- `--pdf` / `--docx` need Pandoc; without it, say so and keep the Markdown.
- Give the user the path of the report (and of the exports).

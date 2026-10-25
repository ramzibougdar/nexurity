# Common pipeline (main thread)

Paths used below:
- `<plugin>`: the plugin folder (`${CLAUDE_PLUGIN_ROOT}`, given in the command that sent you here);
- `<data>`: Nexurity's data folder (`${CLAUDE_PLUGIN_DATA}`);
- `<folder>`: the engagement folder, `./.nexurity/<REF>/` in the folder where Claude Code was started.

Run scripts as `python3 "<plugin>/scripts/<name>.py" …`, always with `--data "<data>"` when they take it.
Log every step: `python3 "<plugin>/scripts/engagement.py" log --data "<data>" --ref <REF> --message "…"`.

0. **Update check**, unless `check_updates` is false in `<data>/config.json`:
   `python3 "<plugin>/scripts/check_updates.py" --data "<data>"` (cached 6 h, 15 s max, never blocks).
   If something is new, show it and ask: Update now (run `/nexurity:update`) · Run with the current versions ·
   Remind me next time. Never update silently. Log the result (or "updates not checked").
1. **Wizard** (`WIZARD.md`), unless `--config` or `--resume`.
2. **Engagement**: `python3 "<plugin>/scripts/engagement.py" start --data "<data>" --session "<session id>"
   --cwd "<current folder>" --kind audit|incident --target "<target>" --lang <en|fr>
   --config <answers.json>`, with `--lang` set to the language of the conversation (the script uses the
   Claude Code `language` setting first when there is one). It prints `{"ref", "folder", "language"}`. From now on the safeguard hook is active for this
   session: only read-only commands run, and files can only be written in `<folder>`.
   Write every intermediate JSON (`recon.json`, `candidates-*.json`, `verdicts-*.json`, `findings.json`)
   with the Write tool into `<folder>`.
3. **Recon** (agent depending on type, see `ROUTING.md`) → `<folder>/recon.json`: languages, frameworks,
   **stack** (detected, never asked), versions, exposed surface, `local` for websites.
4. **Deterministic tools** (`TOOLS.md`) → `<folder>/tools/`. Leads only. Always run
   `python3 "<plugin>/scripts/cms.py" detect <target>` on code; when it finds a CMS, run `cms.py scan` and
   route `hunter-cms` (`ROUTING.md`, "CMS"). Log what it could not check.
5. **Hunters in parallel**: launch all routed hunters **in a single message** (one Agent call each). Give each
   hunter: the target path or URL, `<folder>/recon.json`, the paths of its leads in `<folder>/tools/`, and its
   coverage map (which parts it owns). Each returns only JSON candidates (`REPORT.md`, "Hunter output").
6. **Adversarial verification**: a **fresh verifier per batch** (grouped by file or by vulnerability class).
   It receives only the structured candidates and the paths, never the hunter's prose, and returns
   `confirmed`, `needs_validation` or `rejected` with its reasoning, and the corrected vector.
   Check every vector: `python3 "<plugin>/scripts/cvss4.py" --json "<vector>"`; an invalid one goes back to
   the verifier.
7. **Deduplication** → `<folder>/findings.json` (format in `REPORT.md`): confirmed → "Open",
   needs_validation → "To confirm", rejected → dropped (keep the count in `log.md`). Already fixed → "Fixed".
8. **Report text**: the `report-writer` agent receives `findings.json` and `recon.json` and returns the
   summary, top three priorities, impacts in plain language and action plan, in the report language. Merge
   them into `findings.json` (never change vectors, statuses or evidence).
9. **Render**: `python3 "<plugin>/scripts/render_report.py" --data "<data>" --ref <REF>` → `<folder>/report.md`.
   It refuses invalid vectors and stored scores that differ from the computed ones: fix the JSON, never the
   Markdown. Never write `report.md` by hand.
10. **Close**: `python3 "<plugin>/scripts/engagement.py" close --data "<data>" --ref <REF>`, also when the
    engagement is cancelled or fails. Then give the user the report path, the counts, the rejected-candidate
    count and the tools that did not run.

The report's "Tools" list and approach come from what `log.md` shows was actually done.

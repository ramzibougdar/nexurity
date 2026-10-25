# Start-up wizard

Ask with **`AskUserQuestion`** in the main thread: clickable choices, an "Other" option is always available.
Keep to at most 4 questions per call and 4 options per question; make each screen depend on the previous
answers. Never ask what can be detected (the stack is detected by the recon).

## `/nexurity:audit`

**Screen 1 · Engagement**
- Type: Project code · Server · Live website (passive) · Several
- Goal: Full audit · Diff/PR review · Quick audit · Targeted question
- Audience: Client · Internal use

**Screen 2 · Target** (depending on type)
- Code: local folder (default: the current folder) · Git repository (URL in "Other"; cloned into the
  engagement folder) · branch or PR
- Server: local · SSH (host in "Other"); then access: root · sudo · regular user · shared hosting (logs
  provided manually)
- Website: URL in "Other". If the URL is local (see ROUTING.md), also ask for the project folder (detect
  `~/Sites/<name>`, `~/Herd/<name>` or the current folder) and offer to audit the code too.

**Screen 3 · Scope**
- Areas (multiple choice): code vulnerabilities · dependencies · secrets · server/web configuration
- Depth: quick · standard · thorough
- No stack question: the recap shows "Stack: detected automatically".

**Screen 4 · Client and report**
- Client and project: existing profiles from `<data>/profiles/*.json` (host, URL, access), or "Other"
- Language: English · French (preselected: `language` in `<data>/config.json`)

**Screen 5 · Confirmation**
- Full recap (type, target, scope, depth, client, language, "Stack: detected automatically", estimated
  size: number of files or hosts), then:
  "The client has given written authorisation, including AI-assisted analysis of the material. Start?"
  → Yes · Edit · Cancel

## `/nexurity:incident` (short wizard)

- Symptom: defaced website · suspicious redirects · spam being sent · unknown files · hosting provider alert
- Suspected period: 24 h · 7 days · 30 days · specific date
- Access: SSH root · sudo · regular user · logs provided manually
- Is the website still online? · Time of awareness (date and time, for the 72-hour GDPR deadline)
- Confirmation: recap and authorisation, as above.

## Answers

- Save the answers as JSON (fields of `schemas/audit-config.schema.json`) in a temporary file and pass it
  to `engagement.py start --config <file>`; it ends up in `<folder>/audit-config.json`.
- `--resume <REF>`: reload `<folder>/audit-config.json` of that engagement and go straight to screen 5.
- `--config <file>`: non-interactive mode (CI, scheduled task): no question at all; the file must contain
  `"authorised": true`, otherwise refuse to start.
- Client profiles: offer to save one (`<data>/profiles/<client>.json`, host/URL/access only) at the end of
  a real engagement, only with the user's approval. Never create example profiles.
- During an audit, if a decision is needed (missing tool, access denied), ask instead of guessing.

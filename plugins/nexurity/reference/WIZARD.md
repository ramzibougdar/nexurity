# Start-up wizard

Ask with **`AskUserQuestion`** in the main thread: clickable choices, an "Other" option is always available.
Keep to at most 4 questions per call and 4 options per question; make each screen depend on the previous
answers. Never ask what can be detected or is fixed below.

Nexurity is for internal security use: no client, no audience, no scope, depth or language question, and
no confirmation. The screens below are the only questions.

## Fixed, never asked

- **Scope**: every area that applies to the target (code vulnerabilities, dependencies, secrets,
  server/web configuration, passive website checks).
- **Depth**: thorough, unless the goal is "Quick audit".
- **Stack**: detected automatically by the recon.
- **Report language**: the Claude Code `language` setting; when it is not set, the language the user writes
  in (English or French). `engagement.py start` resolves it: pass `--lang` with the language of the
  conversation, and the script uses the Claude Code setting first when there is one.
- **Start**: no confirmation. After the last screen, show the recap (type, target, "Scope: all areas",
  "Depth: thorough", "Stack: detected automatically", estimated size: number of files or hosts) and start
  straight away.

## `/nexurity:audit`

**Screen 1 · Engagement**
- Type: Project code · Server · Live website (passive) · Several
- Goal: Full audit · Diff/PR review · Quick audit · Targeted question

**Screen 2 · Target** (depending on type)
- Code: local folder (default: the current folder) · Git repository (URL in "Other"; cloned into the
  engagement folder) · branch or PR
- Server: local · SSH (host in "Other"); then access: root · sudo · regular user · shared hosting (logs
  provided manually)
- Website: URL in "Other". If the URL is local (see ROUTING.md), also ask for the project folder (detect
  `~/Sites/<name>`, `~/Herd/<name>` or the current folder) and offer to audit the code too.

Then show the recap and start.

## `/nexurity:incident` (short wizard)

- Symptom: defaced website · suspicious redirects · spam being sent · unknown files · hosting provider alert
- Suspected period: 24 h · 7 days · 30 days · specific date
- Access: SSH root · sudo · regular user · logs provided manually
- Is the website still online? · Time of awareness (date and time, for the 72-hour GDPR deadline)

Then show the recap and start.

## Answers

- Save the answers as JSON (fields of `schemas/audit-config.schema.json`) in a temporary file and pass it
  to `engagement.py start --config <file>`; it ends up in `<folder>/audit-config.json`.
- `--resume <REF>`: reload `<folder>/audit-config.json` of that engagement, show the recap and start.
- `--config <file>`: non-interactive mode (CI, scheduled task): no question at all.
- During an audit, if a decision is needed (missing tool, access denied), ask instead of guessing.

---
name: audit-diff
description: Nexurity review of a diff, a branch or a pull request: only the changed code is audited.
argument-hint: "[base..head | PR number | branch]"
disable-model-invocation: true
---

# Nexurity · diff review

Paths for this run:
- plugin: `${CLAUDE_PLUGIN_ROOT}`
- data: `${CLAUDE_PLUGIN_DATA}`
- session id: `${CLAUDE_SESSION_ID}`
- arguments: `$ARGUMENTS`

Before anything else, read `${CLAUDE_PLUGIN_ROOT}/reference/RULES.md` and follow it for the whole run.

1. Determine the change to review from the argument: a range `base..head`, a branch (compared with the default
   branch), or a pull request (fetch it read-only, for example with `git ls-remote` and a clone into the
   engagement folder, or ask the user for the diff). With no argument, review the uncommitted changes and the
   current branch against its upstream.
2. Ask nothing and start the engagement straight away (`--kind audit`, target = the repository; language
   as in `${CLAUDE_PLUGIN_ROOT}/reference/WIZARD.md`).
3. Collect the diff read-only (`git diff`, `git log`) into `<folder>/diff.patch` with a redirection.
4. Recon on the changed files only (stack, frameworks). Route hunters to the changed files and the code that
   calls them; ignore unchanged code except to understand data flow.
5. Verify every candidate (`verifier`), build `findings.json` limited to issues introduced or touched by the
   change, render the report and close the engagement.
6. Also give a short list of the confirmed findings with file and line, ready to paste as review comments.

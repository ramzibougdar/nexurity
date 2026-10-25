#!/usr/bin/env python3
"""Mask secrets: keep only the first 4 and last 4 characters.

    mask_secrets.py FILE...      print masked content
    cat FILE | mask_secrets.py   mask stdin

Used by render_report.py on evidence, log extracts and indicators of compromise.
Python standard library only.
"""
import re
import sys

# (pattern, group holding the secret)
PATTERNS = [
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), 0),                                # AWS access key
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), 0),                             # GitHub tokens
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), 0),
    (re.compile(r"\bxox[abpors]-[A-Za-z0-9-]{10,}\b"), 0),                          # Slack
    (re.compile(r"\bsk-(?:ant-|proj-|live_|test_)?[A-Za-z0-9_-]{20,}\b"), 0),       # API keys (OpenAI, Anthropic, Stripe…)
    (re.compile(r"\b[rp]k_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0),                   # Stripe
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), 0),                                  # Google API key
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),  # JWT
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), 0),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)([^@\s/]{4,})(@)"), 2),     # credentials in URLs
    (re.compile(
        r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
        r"client[_-]?secret|auth|credentials?|db_pass(?:word)?|_KEY|_SECRET|_TOKEN)[\"']?\s*[:=]\s*[\"']?)"
        r"([^\s\"',;]{6,})"), 2),
]


def mask_value(value):
    if len(value) <= 8:
        return "*" * len(value)
    if value.startswith("-----BEGIN"):
        return "-----BEGIN PRIVATE KEY----- …masked… -----END PRIVATE KEY-----"
    return value[:4] + "…" + value[-4:]


def mask_text(text):
    if not text:
        return text
    for pattern, group in PATTERNS:
        def repl(match, group=group):
            if group == 0:
                return mask_value(match.group(0))
            start, end = match.span(group)
            whole_start = match.start(0)
            g = match.group(0)
            return g[:start - whole_start] + mask_value(match.group(group)) + g[end - whole_start:]
        text = pattern.sub(repl, text)
    return text


def main(argv):
    if len(argv) > 1:
        for path in argv[1:]:
            with open(path, encoding="utf-8", errors="replace") as fh:
                sys.stdout.write(mask_text(fh.read()))
    else:
        sys.stdout.write(mask_text(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""PreToolUse hook: read-only safeguard during a Nexurity engagement.

The plugin is installed globally, so this hook runs in every session. It does
nothing unless the current session has an engagement open
(`<data>/engagements/sessions/<session-id>.json`). During an engagement:

- Edit / Write / MultiEdit / NotebookEdit are allowed only inside the engagement folder;
- Bash commands, local or over `ssh host '…'`, must match an allowlist of read-only
  commands; outputs may only be redirected into the engagement folder (or /dev/null);
- everything else is refused with an explicit reason (exit code 2, reason on stderr).

Python standard library only.
"""
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SEPARATORS = {";", "&&", "||", "|", "&", "|&", "\n"}
REDIRECT_OUT = {">", ">>", ">|", "&>", "&>>", ">&"}
REDIRECT_IN = {"<", "<<<"}
FORBIDDEN_SYNTAX = [
    ("`", "command substitution with backticks"),
    ("$(", "command substitution $(…)"),
    ("<(", "process substitution"),
    (">(", "process substitution"),
    ("<<", "here-documents"),
]

ALWAYS_REFUSED = {
    "rm", "rmdir", "mv", "chmod", "chown", "chgrp", "chattr", "dd", "shred", "truncate", "ln",
    "kill", "killall", "pkill", "reboot", "shutdown", "halt", "poweroff", "service",
    "nmap", "masscan", "nikto", "sqlmap", "hydra", "medusa", "wfuzz", "ffuf", "gobuster",
    "dirb", "dirbuster", "msfconsole", "msfvenom", "nc", "ncat", "netcat", "socat", "telnet",
    "scp", "sftp", "rsync", "wget", "ftp", "su", "passwd", "useradd", "userdel", "usermod",
    "groupadd", "mysqladmin", "eval", "exec", "source", ".", "env", "xargs",
    "bash", "sh", "zsh", "dash", "ksh", "fish", "perl", "ruby", "node", "awk", "gawk", "sed",
    "vi", "vim", "nano", "emacs", "apt-get", "pip", "pip3", "export", "unset", "alias",
}

SIMPLE_READ_ONLY = {
    "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "zgrep", "zcat", "zless",
    "bzcat", "xzcat", "ls", "stat", "wc", "sha256sum", "sha1sum", "md5sum", "journalctl", "last",
    "lastb", "lastlog", "ps", "dig", "host", "nslookup", "whois", "file", "strings", "du", "df",
    "id", "whoami", "hostname", "uname", "uptime", "date", "pwd", "echo", "printf", "sort", "uniq",
    "cut", "tr", "basename", "dirname", "realpath", "readlink", "jq", "diff", "cmp", "getent", "w",
    "who", "free", "lsblk", "true", "false", "test", "column", "nl", "comm", "od", "hexdump", "xxd",
}


class Refused(Exception):
    pass


class Context:
    def __init__(self, engagement, cwd, remote=False, data=None):
        self.folder = engagement["folder"]
        self.engagement = engagement
        self.cwd = cwd or engagement.get("cwd") or os.getcwd()
        self.remote = remote
        self.data = data

    def resolve(self, path):
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.join(self.cwd, path)
        return os.path.normpath(path)

    def in_folder(self, path):
        return common.is_within(self.resolve(path), self.folder)

    def require_in_folder(self, path, what):
        if self.remote:
            raise Refused("%s on the remote host is not allowed: only read commands run over SSH" % what)
        if not self.in_folder(path):
            raise Refused("%s outside the engagement folder (%s): %s" % (what, self.folder, path))


def tokenize(command):
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:
        raise Refused("command could not be parsed safely (%s)" % exc)


def split_segments(tokens):
    segments, current = [], []
    for token in tokens:
        if token in SEPARATORS:
            if current:
                segments.append(current)
            current = []
        elif token in ("(", ")"):
            raise Refused("subshells are not allowed during an engagement")
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def strip_redirections(words, ctx):
    """Remove redirections from a segment, checking their targets."""
    out, i = [], 0
    while i < len(words):
        word = words[i]
        nxt = words[i + 1] if i + 1 < len(words) else None
        if word.isdigit() and nxt in REDIRECT_OUT | REDIRECT_IN:
            i += 1
            continue
        if word in REDIRECT_OUT:
            if nxt is None:
                raise Refused("incomplete redirection")
            if word == ">&" and (nxt.isdigit() or nxt == "-"):
                i += 2
                continue
            if nxt != "/dev/null":
                ctx.require_in_folder(nxt, "writing a redirection")
            i += 2
            continue
        if word in REDIRECT_IN:
            if nxt is None:
                raise Refused("incomplete redirection")
            if word == "<<<":
                raise Refused("here-strings are not allowed during an engagement")
            i += 2
            continue
        out.append(word)
        i += 1
    return out


def positional(args, with_value=()):
    """Arguments that are not options (skipping the values of options in `with_value`)."""
    result, skip = [], False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            if arg in with_value:
                skip = True
            continue
        result.append(arg)
    return result


def option_value(args, names):
    """Values given to any of the options in `names` (as `-o v`, `--opt v` or `--opt=v`)."""
    values = []
    for i, arg in enumerate(args):
        for name in names:
            if arg == name and i + 1 < len(args):
                values.append(args[i + 1])
            elif name.startswith("--") and arg.startswith(name + "="):
                values.append(arg.split("=", 1)[1])
            elif not name.startswith("--") and len(name) == 2 and arg.startswith(name) and len(arg) > 2 and not arg.startswith("--"):
                values.append(arg[2:])
    return values


def first_word(args):
    pos = [a for a in args if not a.startswith("-")]
    return pos[0] if pos else None


# --- per-command rules -------------------------------------------------------

def rule_find(args, ctx):
    for bad in ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"):
        if bad in args:
            raise Refused("find %s is not allowed (it runs or writes)" % bad)


def rule_rg(args, ctx):
    if any(a == "--pre" or a.startswith("--pre=") for a in args):
        raise Refused("rg --pre runs a program")


def rule_options_only(args, ctx, name):
    if any(not a.startswith("-") for a in args):
        raise Refused("%s is only allowed with options (listing)" % name)


def rule_crontab(args, ctx):
    rest = [a for a in args]
    if "-u" in rest:
        i = rest.index("-u")
        del rest[i:i + 2]
    if rest != ["-l"]:
        raise Refused("only `crontab -l` (optionally with -u user) is allowed")


def rule_systemctl(args, ctx):
    verb = first_word(args)
    if verb not in {"status", "list-units", "list-unit-files", "list-timers", "list-sockets",
                    "is-active", "is-enabled", "is-failed", "cat", "show"}:
        raise Refused("only read-only systemctl verbs are allowed (status, list-*, show, cat…)")


def rule_first_in(allowed, label):
    def rule(args, ctx):
        verb = first_word(args)
        if verb not in allowed:
            raise Refused("%s: only %s" % (label, ", ".join(sorted(allowed))))
    return rule


def rule_flags_in(allowed, label):
    def rule(args, ctx):
        flags = [a for a in args if a.startswith("-")]
        if not flags or any(f not in allowed for f in flags):
            raise Refused("%s: only %s" % (label, ", ".join(sorted(allowed))))
    return rule


def rule_dpkg(args, ctx):
    if not args or args[0] not in ("-l", "--list", "-L", "--listfiles", "-s", "--status", "-V", "--verify", "-S", "--search"):
        raise Refused("dpkg: only -l, -L, -s, -S and -V are allowed")


def rule_rpm(args, ctx):
    if not args or not (args[0].startswith("-q") or args[0] in ("-V", "--verify", "--query")):
        raise Refused("rpm: only queries (-q…) and -V are allowed")


def rule_apt(args, ctx):
    if first_word(args) != "list":
        raise Refused("apt: only `apt list` is allowed")


def rule_yum(args, ctx):
    if first_word(args) not in ("list", "check-update", "info", "updateinfo"):
        raise Refused("yum/dnf: only list, check-update, info and updateinfo are allowed")


def rule_php(args, ctx):
    if not args or any(a not in ("-i", "-m", "-v", "--ini") for a in args):
        raise Refused("php: only -i, -m, -v and --ini are allowed")


def rule_docker(args, ctx):
    verb = first_word(args)
    if verb in ("network", "volume"):
        pos = positional(args)
        if len(pos) < 2 or pos[1] not in ("ls", "inspect"):
            raise Refused("docker %s: only ls and inspect are allowed" % verb)
        return
    if verb not in ("ps", "inspect", "images", "version", "info"):
        raise Refused("docker: only ps, inspect, images, version, info, network/volume ls|inspect")


def rule_lynis(args, ctx):
    pos = positional(args, with_value=("--logfile", "--report-file", "--profile"))
    if pos[:2] not in (["audit", "system"], ["show", "version"]):
        raise Refused("lynis: only `lynis audit system` and `lynis show version`")
    for value in option_value(args, ["--logfile", "--report-file"]):
        ctx.require_in_folder(value, "lynis output")


def rule_semgrep(args, ctx):
    if any(a in ("--autofix", "-a") or a.startswith("--autofix") for a in args):
        raise Refused("semgrep --autofix modifies the target")
    if first_word(args) in ("login", "logout", "publish", "ci", "install-semgrep-pro", "lsp", "mcp"):
        raise Refused("semgrep: only local scans are allowed (no login, publish or ci)")
    for value in option_value(args, ["-o", "--output", "--json-output", "--sarif-output", "--text-output"]):
        ctx.require_in_folder(value, "semgrep output")


def rule_composer(args, ctx):
    if first_word(args) not in ("audit", "show", "outdated", "licenses", "validate"):
        raise Refused("composer: only audit, show, outdated, licenses and validate")


def rule_npm(args, ctx):
    pos = positional(args)
    if not pos or pos[0] not in ("audit", "ls", "list", "outdated", "view", "explain"):
        raise Refused("npm: only audit, ls, outdated, view and explain")
    if pos[0] == "audit" and len(pos) > 1:
        raise Refused("npm audit fix (or any audit subcommand) is not allowed")


def rule_pip_audit(args, ctx):
    if "--fix" in args:
        raise Refused("pip-audit --fix modifies the environment")
    for value in option_value(args, ["-o", "--output"]):
        ctx.require_in_folder(value, "pip-audit output")


def rule_cargo(args, ctx):
    pos = positional(args)
    if not pos or pos[0] != "audit" or (len(pos) > 1 and pos[1] == "fix"):
        raise Refused("cargo: only `cargo audit` (not fix)")


def rule_gitleaks(args, ctx):
    if first_word(args) not in ("detect", "dir", "git", "protect", "version", "stdin"):
        raise Refused("gitleaks: only detect, dir, git, protect and version")
    for value in option_value(args, ["-r", "--report-path", "--baseline-path"]):
        ctx.require_in_folder(value, "gitleaks report")


def rule_trufflehog(args, ctx):
    if first_word(args) not in ("filesystem", "git", "github", "gitlab", "docker", "s3"):
        raise Refused("trufflehog: only read-only scan subcommands")


def rule_testssl(args, ctx):
    for name in ("--logfile", "--jsonfile", "--jsonfile-pretty", "--csvfile", "--htmlfile", "-oL", "-oJ", "-oj", "-oC", "-oH", "-oA", "-oa", "--outFile", "--outfile"):
        for value in option_value(args, [name]):
            ctx.require_in_folder(value, "testssl.sh output")


CODEQL_WITH_VALUE = ("--language", "-l", "--source-root", "-s", "--build-mode", "--output", "-o", "--format",
                     "--codescanning-config", "--threads", "-j", "--ram", "-M", "--sarif-category",
                     "--search-path", "--additional-packs", "--working-dir")
CODEQL_NO_BUILD = {"javascript", "javascript-typescript", "typescript", "python", "ruby", "actions", "php"}


def rule_codeql(args, ctx):
    """CodeQL may only extract without building and analyze, writing into the engagement folder."""
    pos = positional(args, with_value=CODEQL_WITH_VALUE)
    if pos[:1] == ["version"] or pos[:2] == ["resolve", "languages"]:
        return
    if any(a in ("--command", "-c", "--download") or a.startswith(("--command=", "--download=")) for a in args):
        raise Refused("codeql: no build command and no pack download (the target is never built or run)")
    for value in option_value(args, ["--search-path", "--additional-packs"]):
        for part in value.split(os.pathsep):
            if not (ctx.data and common.is_within(ctx.resolve(part), os.path.join(ctx.data, "tools"))):
                raise Refused("codeql: extractors and packs only from Nexurity's tools folder")
    if pos[:2] == ["database", "create"]:
        if len(pos) < 3:
            raise Refused("codeql database create needs a database path")
        ctx.require_in_folder(pos[2], "the CodeQL database")
        languages = {l.strip() for v in option_value(args, ["--language", "-l"]) for l in v.split(",") if l.strip()}
        if not languages:
            raise Refused("codeql database create needs --language")
        build_mode = option_value(args, ["--build-mode"])
        if build_mode and build_mode != ["none"]:
            raise Refused("codeql: only --build-mode=none (the target is never built)")
        if not build_mode and not languages <= CODEQL_NO_BUILD:
            raise Refused("codeql: compiled languages need --build-mode=none (the target is never built)")
        return
    if pos[:2] == ["database", "analyze"]:
        if len(pos) < 3:
            raise Refused("codeql database analyze needs a database path")
        ctx.require_in_folder(pos[2], "the CodeQL database")
        outputs = option_value(args, ["--output", "-o"])
        if not outputs:
            raise Refused("codeql database analyze needs --output inside the engagement folder")
        for value in outputs:
            ctx.require_in_folder(value, "CodeQL results")
        return
    raise Refused("codeql: only version, resolve languages, database create and database analyze")


def rule_curl(args, ctx):
    bad = ("-X", "--request", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode",
           "--json", "-F", "--form", "--form-string", "-T", "--upload-file", "-K", "--config",
           "-O", "--remote-name", "--remote-name-all", "-J", "-u", "--user", "--proxy-user")
    for arg in args:
        for b in bad:
            if arg == b or (b.startswith("--") and arg.startswith(b + "=")):
                raise Refused("curl %s is not allowed: only GET/HEAD requests, without credentials" % b)
    for value in option_value(args, ["-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar", "--trace", "--trace-ascii", "--stderr"]):
        if value not in ("/dev/null", "-"):
            ctx.require_in_folder(value, "curl output")


def rule_openssl(args, ctx):
    if not args or args[0] not in ("s_client", "x509", "version", "ciphers", "verify"):
        raise Refused("openssl: only s_client, x509, version, ciphers and verify")
    for value in option_value(args, ["-out", "-sess_out", "-keylogfile", "-msgfile"]):
        ctx.require_in_folder(value, "openssl output")


GIT_READ = {"log", "show", "diff", "status", "rev-parse", "ls-files", "ls-tree", "blame", "describe",
            "cat-file", "shortlog", "grep", "ls-remote", "rev-list", "for-each-ref", "show-ref", "version"}


def rule_git(args, ctx):
    rest = list(args)
    base_dir = None
    while rest and rest[0] in ("-C", "-c", "--no-pager", "--git-dir", "--work-tree"):
        if rest[0] == "-c":
            raise Refused("git -c (configuration override) is not allowed")
        if rest[0] == "-C" and len(rest) > 1:
            base_dir = ctx.resolve(rest[1])
        rest = rest[2:] if rest[0] in ("-C", "--git-dir", "--work-tree") else rest[1:]
    if not rest:
        raise Refused("git: a read-only subcommand is required")
    verb, sub = rest[0], rest[1:]
    if verb in GIT_READ:
        if verb == "diff" and any(a.startswith("--output") for a in sub):
            raise Refused("git diff --output writes a file")
        return
    if verb == "branch" and all(a in ("-a", "-r", "--list", "-v", "-vv", "--all", "--remotes") for a in sub):
        return
    if verb == "remote" and sub in ([], ["-v"], ["show"]):
        return
    if verb == "clone":
        pos = positional(sub, with_value=("--depth", "--branch", "-b", "--origin", "-o", "--filter", "--reference"))
        if len(pos) != 2:
            raise Refused("git clone needs an explicit destination inside the engagement folder")
        if any(a.startswith("--config") or a == "-c" or a.startswith("--template") or a.startswith("--upload-pack") or a == "-u" for a in sub):
            raise Refused("git clone: options that run programs or change configuration are not allowed")
        dest = pos[1]
        if base_dir and not os.path.isabs(os.path.expanduser(dest)):
            dest = os.path.join(base_dir, dest)
        ctx.require_in_folder(dest, "git clone destination")
        return
    raise Refused("git %s is not allowed: only read-only subcommands (log, show, diff, status…) and clone into the engagement folder" % verb)


def rule_mkdir(args, ctx):
    paths = positional(args, with_value=("-m", "--mode"))
    if not paths:
        raise Refused("mkdir: a path is required")
    for path in paths:
        ctx.require_in_folder(path, "creating a folder")


def rule_cp(args, ctx):
    if any(not re.match(r"^-[aprRLvn]+$|^--(archive|recursive|preserve(=\S+)?|dereference|verbose|no-clobber)$", a) for a in args if a.startswith("-")):
        raise Refused("cp: only -a, -p, -r, -R, -L, -v and -n are allowed")
    paths = positional(args)
    if len(paths) < 2:
        raise Refused("cp: a source and a destination are required")
    ctx.require_in_folder(paths[-1], "copying")


def rule_tee(args, ctx):
    for path in positional(args):
        ctx.require_in_folder(path, "tee")


def rule_tar(args, ctx):
    joined = " ".join(args)
    mode_args = [a for a in args if a.startswith("-") or (args and a == args[0])]
    modes = "".join(a.lstrip("-") for a in mode_args if not a.startswith("--"))
    if "t" in modes:
        return
    if "c" in modes:
        for value in option_value(args, ["-f", "--file"]) or [p for p in positional(args)[:1]]:
            ctx.require_in_folder(value, "tar archive")
        if "f" not in modes and "--file" not in joined:
            raise Refused("tar -c needs -f with a file inside the engagement folder")
        return
    if "x" in modes:
        dest = option_value(args, ["-C", "--directory"])
        if not dest:
            raise Refused("tar -x needs -C with a folder inside the engagement folder")
        for value in dest:
            ctx.require_in_folder(value, "extracting")
        return
    raise Refused("tar: only -t (list), -c into the engagement folder and -x with -C into it")


RULES = {
    "find": rule_find,
    "rg": rule_rg,
    "ss": lambda a, c: rule_options_only(a, c, "ss"),
    "netstat": lambda a, c: rule_options_only(a, c, "netstat"),
    "crontab": rule_crontab,
    "systemctl": rule_systemctl,
    "dpkg": rule_dpkg,
    "rpm": rule_rpm,
    "apt": rule_apt,
    "yum": rule_yum,
    "dnf": rule_yum,
    "nginx": rule_flags_in({"-T", "-t", "-V", "-v"}, "nginx: only -T, -t, -V, -v"),
    "apachectl": rule_flags_in({"-S", "-M", "-t", "-v", "-V"}, "apachectl: only -S, -M, -t, -v, -V"),
    "apache2ctl": rule_flags_in({"-S", "-M", "-t", "-v", "-V"}, "apache2ctl: only -S, -M, -t, -v, -V"),
    "httpd": rule_flags_in({"-S", "-M", "-t", "-v", "-V"}, "httpd: only -S, -M, -t, -v, -V"),
    "php": rule_php,
    "docker": rule_docker,
    "lynis": rule_lynis,
    "semgrep": rule_semgrep,
    "composer": rule_composer,
    "npm": rule_npm,
    "pip-audit": rule_pip_audit,
    "cargo": rule_cargo,
    "gitleaks": rule_gitleaks,
    "trufflehog": rule_trufflehog,
    "testssl.sh": rule_testssl,
    "codeql": rule_codeql,
    "testssl": rule_testssl,
    "curl": rule_curl,
    "openssl": rule_openssl,
    "git": rule_git,
    "mkdir": rule_mkdir,
    "cp": rule_cp,
    "tee": rule_tee,
    "tar": rule_tar,
}
LOCAL_ONLY = {"mkdir", "cp", "tee", "tar", "codeql"}

SSH_WITH_VALUE = {"-p", "-i", "-l", "-o", "-F", "-J", "-E", "-b", "-c", "-m", "-S"}
SSH_FORBIDDEN = {"-L", "-R", "-D", "-W", "-w", "-O", "-M", "-N", "-f", "-X", "-Y", "-A"}


def check_ssh(args, ctx):
    if ctx.remote:
        raise Refused("nested ssh is not allowed")
    i = 0
    while i < len(args) and args[i].startswith("-"):
        flag = args[i]
        if flag[:2] in SSH_FORBIDDEN:
            raise Refused("ssh %s (forwarding, multiplexing or background) is not allowed" % flag[:2])
        if flag in SSH_WITH_VALUE:
            i += 2
        else:
            i += 1
    if i >= len(args):
        raise Refused("ssh needs a host")
    remote = args[i + 1:]
    if not remote:
        raise Refused("interactive ssh sessions are not allowed: give the read-only command to run")
    remote_command = " ".join(remote)
    check_command(remote_command, Context(ctx.engagement, ctx.cwd, remote=True))


def check_python(args, ctx):
    if ctx.remote:
        raise Refused("running Python on the remote host is not allowed")
    if args[:2] == ["-m", "json.tool"]:
        return
    if not args:
        raise Refused("interactive Python is not allowed")
    script = os.path.realpath(ctx.resolve(args[0]))
    if os.path.dirname(script) != os.path.realpath(common.SCRIPTS_DIR) or not script.endswith(".py"):
        raise Refused("only Nexurity's own scripts (%s) may run with Python during an engagement" % common.SCRIPTS_DIR)
    check_nexurity_script(os.path.basename(script), args[1:], ctx)


def check_nexurity_script(name, args, ctx):
    """Nexurity's scripts may only write into the engagement folder during an engagement."""
    if name == "engagement.py":
        verb = args[0] if args else ""
        if verb not in ("log", "resolve", "list", "close"):
            raise Refused("engagement.py %s is not allowed while an engagement is open (close it first)" % verb)
    elif name == "render_report.py":
        for value in option_value(args, ["--folder"]):
            ctx.require_in_folder(value, "rendering a report")
    elif name == "preserve_evidence.py":
        dest = option_value(args, ["--dest"])
        if not dest:
            raise Refused("preserve_evidence.py needs --dest inside the engagement folder")
        for value in dest:
            ctx.require_in_folder(value, "preserving evidence")
    elif name == "cms.py":
        verb = args[0] if args else ""
        if verb == "scan":
            out = option_value(args, ["--out"])
            if not out:
                raise Refused("cms.py scan needs --out inside the engagement folder")
            for value in out:
                ctx.require_in_folder(value, "writing the CMS check")
        elif verb != "detect":
            raise Refused("cms.py: only detect and scan")
    elif name == "knowledge.py":
        verb = args[0] if args else ""
        if verb == "ledger":
            folders = option_value(args, ["--folder"])
            if not folders:
                raise Refused("knowledge.py ledger needs --folder (the engagement folder)")
            for value in folders:
                ctx.require_in_folder(value, "writing the knowledge ledger")
        elif verb != "sources":
            raise Refused("knowledge.py: only sources and ledger")
    elif name == "tools.py":
        if (args[0] if args else "") != "where":
            raise Refused("tools.py: only `where` during an engagement; install tools before starting it")
    elif name in ("cvss4.py", "mask_secrets.py", "triage_logs.py", "check_updates.py", "guard.py"):
        return
    else:
        raise Refused("%s is not one of the scripts allowed during an engagement" % name)


def check_segment(words, ctx):
    words = strip_redirections(words, ctx)
    if not words:
        return
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        raise Refused("environment assignments before a command are not allowed")
    name = words[0]
    args = words[1:]
    if "$" in name:
        raise Refused("the command name cannot come from a variable")

    if name == "sudo":
        rest = list(args)
        while rest and rest[0].startswith("-"):
            if rest[0] in ("-u", "-g"):
                rest = rest[2:]
            elif rest[0] in ("-n", "--non-interactive"):
                rest = rest[1:]
            else:
                raise Refused("sudo %s is not allowed (only -n and -u user)" % rest[0])
        if not rest:
            raise Refused("sudo needs a command")
        return check_segment(rest, ctx)
    if name == "timeout":
        rest = [a for a in args if not a.startswith("-")]
        if len(rest) < 2:
            raise Refused("timeout needs a duration and a command")
        return check_segment(rest[1:], ctx)
    if name == "cd":
        if len(args) > 1:
            raise Refused("cd takes one folder")
        if not ctx.remote:
            ctx.cwd = ctx.resolve(args[0] if args else "~")
        return
    if name == "ssh":
        return check_ssh(args, ctx)
    if name in ("python3", "python"):
        return check_python(args, ctx)

    base = os.path.basename(name)
    if "/" in name:
        if base in ("testssl.sh",):
            name = base
        elif not ctx.remote and ctx.data and base in RULES and os.path.realpath(os.path.dirname(ctx.resolve(name))) in {
                os.path.realpath(d) for d in common.managed_tool_dirs(ctx.data)}:
            name = base
        elif os.path.realpath(os.path.dirname(ctx.resolve(name))) == os.path.realpath(common.SCRIPTS_DIR):
            raise Refused("run Nexurity scripts with python3")
        else:
            raise Refused("programs must be called by name, not by path: %s" % name)

    if name in ALWAYS_REFUSED:
        raise Refused("`%s` is never allowed during an engagement (read-only audit)" % name)
    if name in SIMPLE_READ_ONLY:
        return
    rule = RULES.get(name)
    if rule is None:
        raise Refused("`%s` is not in the read-only allowlist (see the Nexurity safeguards)" % name)
    if ctx.remote and name in LOCAL_ONLY:
        raise Refused("`%s` is not allowed on the remote host" % name)
    rule(args, ctx)


def check_command(command, ctx):
    for needle, label in FORBIDDEN_SYNTAX:
        if needle in command:
            raise Refused("%s is not allowed during an engagement" % label)
    command = command.replace("\r", "")
    tokens = tokenize(command.replace("\n", " ; "))
    for segment in split_segments(tokens):
        check_segment(segment, ctx)


def decide(payload, data=None):
    """Return None to allow, or the reason of a refusal."""
    data = common.data_dir(data)
    session = payload.get("session_id")
    if not os.path.isdir(common.sessions_dir(data)):
        return None
    engagement = common.load_session_engagement(data, session, payload.get("cwd"))
    if not engagement:
        return None
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    ctx = Context(engagement, payload.get("cwd"), data=data)
    try:
        if tool in WRITE_TOOLS:
            path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
            if not path or not ctx.in_folder(path):
                raise Refused("during engagement %s, files may only be written in %s" % (engagement["ref"], engagement["folder"]))
        elif tool == "Bash":
            check_command(tool_input.get("command", ""), ctx)
    except Refused as exc:
        return "Nexurity safeguard (%s): %s. Nexurity is read-only on the target; propose the change instead of applying it, or close the engagement with /nexurity:audit --close %s." % (
            engagement["ref"], exc, engagement["ref"])
    return None


def main():
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    reason = decide(payload)
    if reason:
        print(reason, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Shared helpers for the Nexurity scripts: paths, configuration, engagements.

Python standard library only. Every path that matters is passed explicitly by the
skills (`--data "${CLAUDE_PLUGIN_DATA}"`), because the plugin variables are not
set in the environment of commands run through the Bash tool. Hooks receive
CLAUDE_PLUGIN_DATA in their environment.
"""
import datetime
import json
import os
import re
import tempfile

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(PLUGIN_ROOT, "scripts")

DEFAULT_CONFIG = {
    "prefixes": {"audit": "AUD", "incident": "INC"},
    "counters": {},
    "check_updates": True,
    "update_check_cache_hours": 6,
    "semgrep_hook": False,
}

MANAGED_SETTINGS = ["/Library/Application Support/ClaudeCode/managed-settings.json",
                    "/etc/claude-code/managed-settings.json"]

REPORT_LANGUAGES = {"en": ("en", "english", "anglais"),
                    "fr": ("fr", "french", "francais", "français")}


def report_language(value):
    """'en' or 'fr' for a language name or code ("French", "fr-FR"…), else None."""
    value = str(value or "").strip().lower().replace("_", "-").split("-")[0]
    for code, names in REPORT_LANGUAGES.items():
        if value in names:
            return code
    return None


def claude_code_language(cwd):
    """Report language from the Claude Code `language` setting, or None when unset or unsupported.

    Same precedence as Claude Code: managed, then project local, project, then user settings.
    """
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    candidates = MANAGED_SETTINGS + [
        os.path.join(cwd, ".claude", "settings.local.json"),
        os.path.join(cwd, ".claude", "settings.json"),
        os.path.join(config_dir, "settings.json"),
    ]
    for path in candidates:
        settings = read_json(path)
        if isinstance(settings, dict) and settings.get("language"):
            return report_language(settings["language"])
    return None


REF_RE = re.compile(r"^(?P<prefix>[A-Z]{2,5})-(?P<year>\d{4})-(?P<num>\d{3,})$")


def data_dir(explicit=None):
    """Nexurity's persistent data folder (${CLAUDE_PLUGIN_DATA})."""
    for candidate in (explicit, os.environ.get("CLAUDE_PLUGIN_DATA")):
        if candidate and "${" not in candidate:
            return os.path.abspath(os.path.expanduser(candidate))
    return os.path.join(os.path.expanduser("~"), ".claude", "plugins", "data", "nexurity")


def managed_tool_dirs(data):
    """Folders where `tools.py install` puts the audit tools (the safeguard allows calling a tool from them)."""
    return [os.path.join(data, "bin"), os.path.join(data, "venv", "bin"),
            os.path.join(data, "tools", "lynis"), os.path.join(data, "tools", "testssl.sh"),
            os.path.join(data, "tools", "codeql")]


def engagements_dir(data):
    return os.path.join(data, "engagements")


def sessions_dir(data):
    return os.path.join(engagements_dir(data), "sessions")


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default
    except (OSError, ValueError):
        return default


def write_json(path, value):
    """Atomic JSON write."""
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(value, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_config(data):
    path = os.path.join(data, "config.json")
    config = read_json(path)
    if config is None:
        config = json.loads(json.dumps(DEFAULT_CONFIG))
        write_json(path, config)
        return config
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update(config)
    return merged


def save_config(data, config):
    write_json(os.path.join(data, "config.json"), config)


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def is_within(path, folder):
    """True if `path` (after resolving symlinks) is `folder` or inside it."""
    try:
        real_path = os.path.realpath(os.path.expanduser(path))
        real_folder = os.path.realpath(os.path.expanduser(folder))
    except (OSError, ValueError):
        return False
    return real_path == real_folder or real_path.startswith(real_folder.rstrip(os.sep) + os.sep)


def session_file(data, session_id):
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id or "")
    return os.path.join(sessions_dir(data), safe + ".json")


def load_session_engagement(data, session_id, cwd=None):
    """Engagement of a session, claiming a pending one started from the same folder.

    A skill passes ${CLAUDE_SESSION_ID}; if it was not substituted, engagement.py
    stores the engagement as pending, and the first hook call of the session that
    runs in the same folder claims it.
    """
    if not session_id:
        return None
    path = session_file(data, session_id)
    engagement = read_json(path)
    if engagement:
        return engagement
    if not cwd:
        return None
    folder = sessions_dir(data)
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return None
    for name in names:
        if not name.startswith("pending-"):
            continue
        pending_path = os.path.join(folder, name)
        pending = read_json(pending_path)
        if not pending or os.path.realpath(pending.get("cwd", "")) != os.path.realpath(cwd):
            continue
        pending["session_id"] = session_id
        write_json(path, pending)
        try:
            os.unlink(pending_path)
        except OSError:
            pass
        return pending
    return None

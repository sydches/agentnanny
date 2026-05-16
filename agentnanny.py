#!/usr/bin/env python3
"""agentnanny — granular permission manager for Claude Code and Codex CLI."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_PATH = Path(__file__).resolve()
CONFIG_PATH = SCRIPT_PATH.parent / "config.toml"
SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
CLAUDE_JSON_PATH = Path.home() / ".claude.json"
PID_FILE = Path("/tmp/agentnanny.pid") if sys.platform != "win32" else Path(os.environ.get("TEMP", "/tmp")) / "agentnanny.pid"
SESSION_DIR = Path(tempfile.gettempdir()) / "agentnanny" / "sessions"

# Codex CLI paths
CODEX_HOME = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
CODEX_CONFIG_PATH = CODEX_HOME / "config.toml"
CODEX_TRUST_PATH = CODEX_HOME / "trust.json"

# Supported targets
TARGETS = ("claude", "codex")

# Map agentnanny profiles to Codex approval_policy values
CODEX_APPROVAL_MAP: dict[str, str] = {
    "reviewer": "unless-trusted",
    "safe-dev": "unless-trusted",
    "full-dev": "on-failure",
    "overnight": "on-failure",
    "ci-runner": "never",
}

# ---------------------------------------------------------------------------
# Built-in groups and profiles (work without any config file)
# ---------------------------------------------------------------------------

BUILTIN_GROUPS: dict[str, list[str]] = {
    "read-only":    ["Read", "Glob", "Grep"],
    "write":        ["Write", "Edit"],
    "filesystem":   ["Read", "Write", "Edit", "Glob", "Grep"],
    "shell":        ["Bash"],
    "safe-shell":   ["Bash(ls*)", "Bash(cat*)", "Bash(head*)", "Bash(grep*)", "Bash(find*)"],
    "review-shell": ["Bash(git log*)", "Bash(git diff*)", "Bash(git show*)", "Bash(git blame*)"],
    "network":      ["WebFetch", "WebSearch"],
    "all":          [".*"],
}

BUILTIN_PROFILES: dict[str, dict] = {
    "safe-dev": {
        "groups": ["filesystem", "safe-shell"],
        "deny": [],
        "ttl": "8h",
    },
    "full-dev": {
        "groups": ["filesystem", "shell", "network"],
        "deny": ["Bash(rm -rf /*)", "Bash(DROP TABLE*)", "Bash(git push --force*)"],
        "ttl": "8h",
    },
    "reviewer": {
        "groups": ["read-only", "review-shell"],
        "deny": [],
        "ttl": "4h",
    },
    "overnight": {
        "groups": ["filesystem", "shell", "network"],
        "deny": ["Bash(git push --force*)", "Bash(git reset --hard*)"],
        "ttl": "12h",
    },
    "ci-runner": {
        "groups": ["filesystem", "shell"],
        "deny": ["Bash(curl*|*sh)", "Bash(wget*|*sh)", "WebFetch", "WebSearch"],
        "ttl": "1h",
    },
}

# ---------------------------------------------------------------------------
# Config path helpers
# ---------------------------------------------------------------------------


def _user_config_path() -> Path:
    """Return user-level config path. APPDATA on Windows, XDG on Linux/macOS."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "agentnanny" / "config.toml"


def _find_project_config() -> Path | None:
    """Walk up from cwd looking for .agentnanny.toml."""
    current = Path.cwd().resolve()
    for parent in [current, *current.parents]:
        candidate = parent / ".agentnanny.toml"
        if candidate.is_file():
            return candidate
    return None


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Merge overlay into base. Dict values merge recursively; others replaced."""
    result = dict(base)
    for key, val in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


# ---------------------------------------------------------------------------
# Minimal TOML parser (stdlib only — handles flat tables, strings, arrays)
# ---------------------------------------------------------------------------


def parse_toml(text: str) -> dict:
    """Parse a subset of TOML sufficient for config.toml."""
    result: dict = {}
    current_table: dict = result
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Table header
        m = re.match(r"^\[([a-zA-Z0-9_.:-]+)\]$", line)
        if m:
            parts = m.group(1).split(".")
            current_table = result
            for p in parts:
                current_table = current_table.setdefault(p, {})
            continue
        # Key = value
        m = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*(.+)$', line)
        if not m:
            continue
        key, raw = m.group(1), m.group(2).strip()
        current_table[key] = _parse_toml_value(raw)
    return result


def _parse_toml_value(raw: str):
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'"):
        return raw[1:-1]
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.startswith("["):
        # Simple flat array of strings
        inner = raw[1:-1].strip()
        if not inner:
            return []
        items = []
        for item in re.findall(r'"([^"]*)"', inner):
            items.append(item)
        return items
    try:
        return float(raw) if "." in raw else int(raw)
    except ValueError:
        return raw


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_config() -> dict:
    """Load config with layered merge: builtins -> script-adjacent -> user -> project -> env vars."""
    cfg: dict = {
        "hooks": {},
        "daemon": {},
        "logging": {},
        "context": {},
        "groups": dict(BUILTIN_GROUPS),
        "profiles": {k: dict(v) for k, v in BUILTIN_PROFILES.items()},
    }

    def _load_toml(path: Path) -> dict:
        if tomllib is not None:
            with open(path, "rb") as fp:
                return tomllib.load(fp)
        return parse_toml(path.read_text(encoding="utf-8"))

    # Layer 1: script-adjacent config.toml (backward compat)
    if CONFIG_PATH.exists():
        cfg = _deep_merge(cfg, _load_toml(CONFIG_PATH))

    # Layer 2: user config (~/.config/agentnanny/config.toml or %APPDATA%)
    user_path = _user_config_path()
    if user_path.exists():
        cfg = _deep_merge(cfg, _load_toml(user_path))

    # Layer 3: project config (.agentnanny.toml walking up from cwd)
    proj_path = _find_project_config()
    if proj_path is not None:
        cfg = _deep_merge(cfg, _load_toml(proj_path))

    # Layer 4: env var overrides
    if v := os.environ.get("AGENTNANNY_SESSION"):
        cfg.setdefault("daemon", {})["session"] = v
    if v := os.environ.get("AGENTNANNY_DENY"):
        cfg.setdefault("hooks", {})["deny"] = [x.strip() for x in v.split(",")]
    if v := os.environ.get("AGENTNANNY_LOG"):
        cfg.setdefault("logging", {})["audit_log"] = v
    if v := os.environ.get("AGENTNANNY_DRY_RUN"):
        cfg.setdefault("daemon", {})["dry_run"] = v.lower() in ("1", "true", "yes")

    return cfg


# ---------------------------------------------------------------------------
# Glob-to-regex conversion
# ---------------------------------------------------------------------------


def _glob_to_regex(pattern: str) -> str:
    """Convert a glob pattern (with ``|`` alternation) to a regex string.

    Each ``|``-separated segment is converted independently (``*`` → ``.*``,
    ``?`` → ``.``) and the segments are joined with ``|``.
    """
    parts: list[str] = []
    for segment in pattern.split("|"):
        parts.append(re.escape(segment).replace(r"\*", ".*").replace(r"\?", "."))
    return "|".join(parts)


# ---------------------------------------------------------------------------
# Deny-list matching
# ---------------------------------------------------------------------------


def matches_deny(tool_name: str, tool_input: dict, deny_list: list[str]) -> bool:
    """Check if a tool call matches any deny pattern.

    Pattern formats:
        "Bash"              — exact tool name match
        "Bash(rm*)"         — tool name + command pattern (glob-style)
        "Bash(rm -rf*)"     — tool name + command prefix
        ".*dangerous.*"     — regex against tool_name
    """
    for pattern in deny_list:
        # Pattern with tool_input filter: ToolName(input_pattern)
        m = re.match(r'^(\w+)\((.+)\)$', pattern)
        if m:
            pat_tool, pat_input = m.group(1), m.group(2)
            if pat_tool != tool_name:
                continue
            # Match against the primary input field (command for Bash, etc.)
            input_str = _primary_input(tool_name, tool_input)
            regex = _glob_to_regex(pat_input)
            if re.match(regex, input_str):
                return True
        else:
            # Plain pattern — match against tool_name
            if pattern == tool_name:
                return True
            try:
                if re.fullmatch(pattern, tool_name):
                    return True
            except re.error:
                pass
    return False


def _primary_input(tool_name: str, tool_input: dict) -> str:
    """Extract the primary input string for a tool call."""
    if tool_name == "Bash":
        return tool_input.get("command", "")
    if tool_name == "Write":
        return tool_input.get("file_path", "")
    if tool_name == "Edit":
        return tool_input.get("file_path", "")
    if tool_name == "Read":
        return tool_input.get("file_path", "")
    if tool_name == "WebFetch":
        return tool_input.get("url", "")
    # Fallback: join all values
    return " ".join(str(v) for v in tool_input.values())


# ---------------------------------------------------------------------------
# Session policies
# ---------------------------------------------------------------------------


_SCOPE_ID_RE = re.compile(r"^[a-f0-9]{8}$")


def _valid_scope_id(scope_id: str) -> bool:
    """Return True if scope_id is a valid 8-char lowercase hex string."""
    return bool(_SCOPE_ID_RE.fullmatch(scope_id))


def generate_scope_id() -> str:
    """Generate a random 8-char hex scope ID."""
    return os.urandom(4).hex()


def save_session_policy(policy: dict) -> Path:
    """Write a session policy file with hardened permissions. Returns the path."""
    if sys.platform == "win32":
        os.makedirs(SESSION_DIR, exist_ok=True)
    else:
        try:
            os.makedirs(SESSION_DIR, mode=0o700, exist_ok=True)
        except PermissionError:
            # Some non-windows-like runtimes reject mode bits on intermediate dirs.
            # Fall back to default directory permissions and continue.
            os.makedirs(SESSION_DIR, exist_ok=True)
    path = SESSION_DIR / f"{policy['scope_id']}.json"
    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(str(tmp), str(path))
    return path


def load_session_policy(scope_id: str) -> dict | None:
    """Load a session policy by scope ID. Returns None if missing or expired."""
    if not _valid_scope_id(scope_id):
        return None
    path = SESSION_DIR / f"{scope_id}.json"
    if not path.exists():
        return None
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    ttl = policy.get("ttl_seconds", 0)
    if ttl > 0:
        created = datetime.fromisoformat(policy["created"])
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        if elapsed > ttl:
            path.unlink(missing_ok=True)
            return None
    return policy


def delete_session_policy(scope_id: str) -> bool:
    """Delete a session policy. Returns True if it existed."""
    if not _valid_scope_id(scope_id):
        return False
    path = SESSION_DIR / f"{scope_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def list_session_policies() -> list[dict]:
    """List all active (non-expired) session policies."""
    if not SESSION_DIR.exists():
        return []
    policies = []
    for path in SESSION_DIR.glob("*.json"):
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        ttl = policy.get("ttl_seconds", 0)
        if ttl > 0:
            created = datetime.fromisoformat(policy["created"])
            elapsed = (datetime.now(timezone.utc) - created).total_seconds()
            if elapsed > ttl:
                path.unlink(missing_ok=True)
                continue
        policies.append(policy)
    return policies


# ---------------------------------------------------------------------------
# Group resolution
# ---------------------------------------------------------------------------


def resolve_groups(group_names: list[str], cfg: dict) -> list[str]:
    """Expand group names to a flat list of tool patterns."""
    groups_cfg = cfg.get("groups", {})
    patterns: list[str] = []
    for name in group_names:
        group_patterns = groups_cfg.get(name)
        if group_patterns is None:
            raise ValueError(f"Unknown group: {name}")
        patterns.extend(group_patterns)
    return patterns


# ---------------------------------------------------------------------------
# Profile resolution
# ---------------------------------------------------------------------------


def resolve_profile(name: str, cfg: dict) -> dict:
    """Look up a profile by name. Returns dict with keys: groups, deny, ttl."""
    profiles = cfg.get("profiles", {})
    profile = profiles.get(name)
    if profile is None:
        available = ", ".join(sorted(profiles))
        raise ValueError(f"Unknown profile: {name}. Available: {available}")
    return {
        "groups": list(profile.get("groups", [])),
        "deny": list(profile.get("deny", [])),
        "ttl": str(profile.get("ttl", "0")),
    }


# ---------------------------------------------------------------------------
# Allow matching
# ---------------------------------------------------------------------------


def matches_allow(tool_name: str, tool_input: dict, allow_patterns: list[str]) -> bool:
    """Check if a tool call matches any allow pattern.

    Same pattern syntax as matches_deny:
        "Bash"              — exact tool name
        "Bash(ls*)"         — tool name + input pattern
        ".*"                — regex wildcard (match all)
    """
    for pattern in allow_patterns:
        m = re.match(r'^(\w+)\((.+)\)$', pattern)
        if m:
            pat_tool, pat_input = m.group(1), m.group(2)
            if pat_tool != tool_name:
                continue
            input_str = _primary_input(tool_name, tool_input)
            regex = _glob_to_regex(pat_input)
            if re.match(regex, input_str):
                return True
        else:
            if pattern == tool_name:
                return True
            try:
                if re.fullmatch(pattern, tool_name):
                    return True
            except re.error:
                pass
    return False


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def _rotate_log(log_path: str, backup_count: int) -> None:
    """Rotate log files: .log → .log.1, .log.1 → .log.2, etc."""
    # Drop the oldest backup if at limit
    oldest = f"{log_path}.{backup_count}"
    if Path(oldest).exists():
        Path(oldest).unlink()
    # Shift existing backups up
    for i in range(backup_count - 1, 0, -1):
        src = f"{log_path}.{i}"
        dst = f"{log_path}.{i + 1}"
        if Path(src).exists():
            os.replace(src, dst)
    # Move current log to .1
    if Path(log_path).exists():
        os.replace(log_path, f"{log_path}.1")


def audit_log(source: str, action: str, tool_name: str, detail: str, cfg: dict | None = None):
    """Append a TSV line to the audit log with hardened permissions and size-based rotation."""
    cfg = cfg or load_config()
    log_cfg = cfg.get("logging", {})
    level = log_cfg.get("level", "actions")
    log_path = log_cfg.get("audit_log", "/tmp/agentnanny.log")
    max_size_bytes = int(log_cfg.get("max_size_bytes", 10485760))
    backup_count = int(log_cfg.get("backup_count", 3))

    if level == "actions" and action not in ("allowed", "denied", "approved", "expanded"):
        return

    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    line = f"{ts}\t{source}\t{action}\t{tool_name}\t{detail}\n"
    try:
        # Size-based rotation
        p = Path(log_path)
        if p.exists() and p.stat().st_size >= max_size_bytes:
            _rotate_log(log_path, backup_count)
        # Open with hardened permissions (0o600)
        fd = os.open(log_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        pass  # Log failure is not fatal


# ---------------------------------------------------------------------------
# Codex CLI integration
# ---------------------------------------------------------------------------


def _serialize_toml_value(value: object) -> str:
    """Serialize a Python value to a TOML-compatible string."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, list):
        items = ", ".join(_serialize_toml_value(v) for v in value)
        return f"[{items}]"
    raise TypeError(f"Unsupported TOML type: {type(value)}")


def _patch_codex_config(updates: dict[str, object]) -> Path:
    """Read ~/.codex/config.toml, apply key=value updates, write back.

    Only touches top-level keys. Preserves existing content and comments
    by replacing matching lines or inserting new ones before the first table.
    """
    CODEX_HOME.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if CODEX_CONFIG_PATH.exists():
        lines = CODEX_CONFIG_PATH.read_text(encoding="utf-8").splitlines()

    remaining = dict(updates)
    new_lines: list[str] = []
    in_top_level = True
    first_table_idx: int | None = None
    for line in lines:
        stripped = line.strip()
        matched = False
        if stripped.startswith("[") and stripped.endswith("]"):
            in_top_level = False
            if first_table_idx is None:
                first_table_idx = len(new_lines)
        for key in list(remaining):
            if stripped.startswith(f"{key} ") or stripped.startswith(f"{key}="):
                matched = True
                if in_top_level:
                    new_lines.append(f"{key} = {_serialize_toml_value(remaining.pop(key))}")
                break
        if not matched:
            new_lines.append(line)

    if remaining:
        insert_at = first_table_idx if first_table_idx is not None else len(new_lines)
        insert_lines = [
            f"{key} = {_serialize_toml_value(val)}"
            for key, val in remaining.items()
        ]
        new_lines[insert_at:insert_at] = insert_lines

    content = "\n".join(new_lines) + "\n"
    CODEX_CONFIG_PATH.write_text(content, encoding="utf-8")
    return CODEX_CONFIG_PATH


def _remove_codex_config_keys(keys: list[str]) -> bool:
    """Remove specific top-level keys from ~/.codex/config.toml."""
    if not CODEX_CONFIG_PATH.exists():
        return False
    lines = CODEX_CONFIG_PATH.read_text(encoding="utf-8").splitlines()
    new_lines = []
    removed = False
    for line in lines:
        stripped = line.strip()
        if any(stripped.startswith(f"{k} ") or stripped.startswith(f"{k}=") for k in keys):
            removed = True
            continue
        new_lines.append(line)
    if removed:
        CODEX_CONFIG_PATH.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return removed


_BASH_PATTERN_RE = re.compile(r'^Bash\((.+)\)$')


def _codex_prefix_pattern(prefix: str) -> str:
    """Render a shell prefix as a Codex argv-style Starlark pattern list."""
    try:
        parts = shlex.split(prefix)
    except ValueError:
        parts = [prefix]
    if not parts:
        parts = [prefix]
    return "[" + ", ".join(json.dumps(part) for part in parts) + "]"


def _patterns_to_codex_rules(patterns: list[str], decision: str) -> str:
    """Convert agentnanny Bash patterns to Codex Starlark exec policy rules.

    Only Bash(...) patterns translate — non-Bash tool patterns are skipped
    since Codex controls file operations via approval_policy, not exec rules.
    Returns empty string when no patterns match.
    """
    if decision not in ("forbidden", "allow"):
        raise ValueError(f"Invalid codex rule decision: {decision!r}")
    justification = "blocked" if decision == "forbidden" else "allowed"
    rules: list[str] = []
    for pattern in patterns:
        m = _BASH_PATTERN_RE.match(pattern)
        if not m:
            continue
        for segment in m.group(1).split("|"):
            prefix = segment.rstrip("*").rstrip()
            if prefix:
                rules.append(
                    f'prefix_rule(pattern={_codex_prefix_pattern(prefix)}, decision="{decision}",'
                    f' justification="{justification} by agentnanny")'
                )
    return "\n".join(rules)


def _write_codex_rules(scope_id: str, content: str) -> Path:
    """Write an exec policy rules file for the given scope."""
    rules_dir = CODEX_HOME / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    path = rules_dir / f"agentnanny-{scope_id}.rules"
    path.write_text(content, encoding="utf-8")
    return path


def _remove_codex_rules(scope_id: str) -> bool:
    """Remove the exec policy rules file for the given scope."""
    path = CODEX_HOME / "rules" / f"agentnanny-{scope_id}.rules"
    if path.exists():
        path.unlink()
        return True
    return False


def _remove_all_codex_rules() -> int:
    """Remove all agentnanny-generated exec policy rules files."""
    rules_dir = CODEX_HOME / "rules"
    if not rules_dir.exists():
        return 0
    count = 0
    for path in rules_dir.glob("agentnanny-*.rules"):
        path.unlink()
        count += 1
    return count


def install_codex_hooks():
    """Register agentnanny as a notify handler in ~/.codex/config.toml."""
    if CODEX_CONFIG_PATH.exists():
        if HOOK_MARKER in CODEX_CONFIG_PATH.read_text(encoding="utf-8"):
            print(f"Already installed in {CODEX_CONFIG_PATH}", file=sys.stderr)
            raise SystemExit(1)

    python_cmd = sys.executable.replace("\\", "/")
    script_path = str(SCRIPT_PATH).replace("\\", "/")
    notify_argv = [python_cmd, script_path, "codex-hook"]

    _patch_codex_config({"notify": notify_argv})
    print(f"Installed notify hook in {CODEX_CONFIG_PATH}")


def uninstall_codex_hooks():
    """Remove agentnanny notify handler from ~/.codex/config.toml."""
    if not CODEX_CONFIG_PATH.exists():
        print("No Codex config file found", file=sys.stderr)
        raise SystemExit(1)

    removed = _remove_codex_config_keys(["notify"])
    if not removed:
        print("No agentnanny hooks found in Codex config", file=sys.stderr)
        raise SystemExit(1)

    count = _remove_all_codex_rules()
    print(f"Removed agentnanny hooks from {CODEX_CONFIG_PATH}")
    if count:
        print(f"Removed {count} exec policy rules file(s)")


def handle_codex_hook():
    """Codex notify hook handler. Receives tool execution info for audit logging."""
    event = json.load(sys.stdin)
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})

    cfg = load_config()
    detail = ""
    if isinstance(tool_input, dict):
        # Codex LocalShell input has a command array
        cmd = tool_input.get("command", [])
        if isinstance(cmd, list):
            detail = " ".join(cmd)[:200]
        else:
            detail = str(cmd)[:200]
    audit_log("codex-hook", "executed", tool_name, detail, cfg)


def _apply_codex_session(policy: dict, cfg: dict, scope_id: str):
    """Apply an agentnanny session policy to Codex config and rules."""
    # Determine approval_policy from profile or groups
    profile_name = policy.get("_profile_name")
    approval = CODEX_APPROVAL_MAP.get(profile_name or "", "on-request")

    updates: dict[str, object] = {"approval_policy": approval}
    _patch_codex_config(updates)

    # Generate exec policy rules from deny + allow patterns
    deny_patterns = policy.get("deny", [])
    allow_groups = policy.get("allow_groups", [])
    allow_tools = policy.get("allow_tools", [])

    allow_patterns: list[str] = list(allow_tools)
    if allow_groups:
        try:
            allow_patterns.extend(resolve_groups(allow_groups, cfg))
        except ValueError as exc:
            print(f"Warning: {exc}", file=sys.stderr)

    deny_rules = _patterns_to_codex_rules(deny_patterns, "forbidden")
    allow_rules = _patterns_to_codex_rules(allow_patterns, "allow")

    if deny_rules or allow_rules:
        rules_parts = ["# Generated by agentnanny — do not edit manually"]
        if deny_rules:
            rules_parts.append(deny_rules)
        if allow_rules:
            rules_parts.append(allow_rules)
        content = "\n".join(rules_parts) + "\n"
        path = _write_codex_rules(scope_id, content)
        print(f"# Codex rules: {path}", file=sys.stderr)

    print(f"# Codex approval_policy: {approval}", file=sys.stderr)


def _remove_codex_session(scope_id: str):
    """Remove Codex artifacts for a session."""
    _remove_codex_rules(scope_id)
    _remove_codex_config_keys(["approval_policy"])


# ---------------------------------------------------------------------------
# Mode 1: Hook handler (Claude Code)
# ---------------------------------------------------------------------------


def _hook_deny(tool_name: str, message: str, cfg: dict):
    """Output a deny decision and audit log it."""
    audit_log("hook", "denied", tool_name, message, cfg)
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": f"agentnanny: {message}",
            },
        }
    }, sys.stdout)


def _hook_allow(tool_name: str, detail: str, cfg: dict):
    """Output an allow decision and audit log it."""
    audit_log("hook", "allowed", tool_name, detail, cfg)
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }, sys.stdout)


def handle_hook():
    """PermissionRequest hook handler. Reads JSON from stdin, writes decision to stdout.

    Two modes:
      - Legacy (no AGENTNANNY_SCOPE): uses config.toml deny/allow lists, identical to v1
      - Session-scoped (AGENTNANNY_SCOPE set): loads session policy, applies its rules.
        Passthrough (no output, exit 0) when scope is missing/expired or tool not in allow list.
    """
    event = json.load(sys.stdin)
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})

    cfg = load_config()
    global_deny = cfg.get("hooks", {}).get("deny", [])

    # Global deny always applies regardless of mode
    if matches_deny(tool_name, tool_input, global_deny):
        _hook_deny(tool_name, f"denied {tool_name}", cfg)
        return

    scope_id = os.environ.get("AGENTNANNY_SCOPE")

    if not scope_id:
        # No active scope — check for explicit allow list in config
        allow_list = cfg.get("hooks", {}).get("allow", None)
        if allow_list is None:
            # No scope, no allow list → passthrough to normal permission dialog
            return
        # Explicit allow list set → enforce it
        if tool_name not in allow_list:
            _hook_deny(tool_name, f"{tool_name} not in allow list", cfg)
            return
        detail = _primary_input(tool_name, tool_input)[:200]
        _hook_allow(tool_name, detail, cfg)
        return

    # Session-scoped mode
    policy = load_session_policy(scope_id)
    if policy is None:
        # No valid policy — passthrough to normal permission dialog
        return

    # Session-level deny (merged with global, which was already checked)
    session_deny = policy.get("deny", [])
    if session_deny and matches_deny(tool_name, tool_input, session_deny):
        _hook_deny(tool_name, f"denied {tool_name} (session {scope_id})", cfg)
        return

    # Resolve session allow list from groups + explicit tools
    allow_patterns: list[str] = list(policy.get("allow_tools", []))
    group_names = policy.get("allow_groups", [])
    if group_names:
        try:
            allow_patterns.extend(resolve_groups(group_names, cfg))
        except ValueError as exc:
            print(f"Warning: {exc}", file=sys.stderr)

    if matches_allow(tool_name, tool_input, allow_patterns):
        detail = _primary_input(tool_name, tool_input)[:200]
        _hook_allow(tool_name, f"{detail} (session {scope_id})", cfg)
        return

    # Tool not in session's allow list — passthrough to normal permission dialog
    return


def handle_post_hook():
    """PostToolUse hook handler. Monitors context pressure."""
    event = json.load(sys.stdin)
    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {})

    cfg = load_config()
    detail = _primary_input(tool_name, tool_input)[:200]
    audit_log("hook", "executed", tool_name, detail, cfg)

    status_path = Path.home() / ".claude" / "status.json"
    if not status_path.exists():
        return

    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return

    context_percent = status.get("contextPercent")
    if context_percent is None:
        return

    ctx_cfg = cfg.get("context", {})
    critical = ctx_cfg.get("critical_percent", 75)
    warn = ctx_cfg.get("warn_percent", 60)

    message: str | None = None
    if context_percent >= critical:
        message = f"agentnanny: CRITICAL — context {context_percent}% full. Summarize and compact immediately."
    elif context_percent >= warn:
        message = f"agentnanny: WARNING — context {context_percent}% full. Consider summarizing soon."

    if message is not None:
        json.dump({"hookSpecificOutput": {"message": message}}, sys.stdout)


# ---------------------------------------------------------------------------
# Mode 2: Install / Uninstall hooks
# ---------------------------------------------------------------------------

HOOK_MARKER = "agentnanny"


def install_hooks():
    """Register agentnanny as a PermissionRequest hook in Claude Code settings."""
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings: dict = {}
    if SETTINGS_PATH.exists():
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))

    hooks = settings.setdefault("hooks", {})
    perm_hooks: list = hooks.setdefault("PermissionRequest", [])

    # Check if already installed
    for entry in perm_hooks:
        for h in entry.get("hooks", []):
            if HOOK_MARKER in h.get("command", ""):
                print(f"Already installed in {SETTINGS_PATH}", file=sys.stderr)
                raise SystemExit(1)

    script_path = str(SCRIPT_PATH)
    # Use forward slashes for cross-platform compatibility
    script_path = script_path.replace("\\", "/")

    # Use absolute path to the interpreter that ran install — avoids PATH differences
    # between the user's shell and Claude Code's hook execution environment
    python_cmd = sys.executable.replace("\\", "/")

    hook_entry = {
        "matcher": "",
        "hooks": [{
            "type": "command",
            "command": f'"{python_cmd}" "{script_path}" hook',
        }],
    }

    perm_hooks.append(hook_entry)

    # Register PostToolUse hook for context pressure monitoring
    post_hooks: list = hooks.setdefault("PostToolUse", [])
    already_installed = any(
        HOOK_MARKER in h.get("command", "")
        for entry in post_hooks
        for h in entry.get("hooks", [])
    )
    if not already_installed:
        post_hook_entry = {
            "matcher": "",
            "hooks": [{
                "type": "command",
                "command": f'"{python_cmd}" "{script_path}" post-hook',
            }],
        }
        post_hooks.append(post_hook_entry)

    SETTINGS_PATH.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Installed PermissionRequest hook in {SETTINGS_PATH}")
    print(f"Installed PostToolUse hook in {SETTINGS_PATH}")


def uninstall_hooks():
    """Remove agentnanny hooks from Claude Code settings."""
    if not SETTINGS_PATH.exists():
        print("No settings file found", file=sys.stderr)
        raise SystemExit(1)

    settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    hooks = settings.get("hooks", {})
    modified = False

    for event_name in ("PermissionRequest", "PreToolUse", "PostToolUse"):
        entries: list = hooks.get(event_name, [])
        filtered = []
        for entry in entries:
            keep = True
            for h in entry.get("hooks", []):
                if HOOK_MARKER in h.get("command", ""):
                    keep = False
                    break
            if keep:
                filtered.append(entry)
        if len(filtered) != len(entries):
            hooks[event_name] = filtered
            modified = True
        # Clean up empty lists
        if not hooks.get(event_name):
            hooks.pop(event_name, None)

    if not modified:
        print("No agentnanny hooks found", file=sys.stderr)
        raise SystemExit(1)

    # Clean up empty hooks dict
    if not hooks:
        settings.pop("hooks", None)

    SETTINGS_PATH.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Removed agentnanny hooks from {SETTINGS_PATH}")


# ---------------------------------------------------------------------------
# Trust directory
# ---------------------------------------------------------------------------


def trust_directory(directory: str):
    """Write trust entry to ~/.claude.json so the trust prompt never appears."""
    abs_dir = str(Path(directory).resolve())
    settings: dict = {}
    if CLAUDE_JSON_PATH.exists():
        settings = json.loads(CLAUDE_JSON_PATH.read_text(encoding="utf-8"))

    projects = settings.setdefault("projects", {})
    proj = projects.setdefault(abs_dir, {})
    proj["hasTrustDialogAccepted"] = True

    CLAUDE_JSON_PATH.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Trusted: {abs_dir}")


def _load_codex_trusts() -> dict[str, dict]:
    """Load Codex trust metadata from CODEX_TRUST_PATH."""
    if not CODEX_TRUST_PATH.exists():
        return {"trusted_directories": []}
    try:
        data = json.loads(CODEX_TRUST_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("trusted_directories"), list):
            return data
    except (json.JSONDecodeError, OSError):
        return {"trusted_directories": []}
    return {"trusted_directories": []}


def _write_codex_trusts(data: dict) -> None:
    """Persist Codex trust metadata with owner-only permissions."""
    CODEX_HOME.mkdir(parents=True, exist_ok=True)
    tmp = CODEX_TRUST_PATH.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(str(tmp), CODEX_TRUST_PATH)


def _add_codex_trusted_directory(directory: str) -> str:
    """Add a directory to Codex trust metadata and return the canonical path."""
    abs_dir = str(Path(directory).resolve())
    data = _load_codex_trusts()
    trusted = data.get("trusted_directories", [])
    if abs_dir not in trusted:
        trusted.append(abs_dir)
        trusted.sort()
    data["trusted_directories"] = trusted
    _write_codex_trusts(data)
    return abs_dir


def _is_codex_trusted(directory: str) -> bool:
    """Return True if the directory is in Codex trust metadata."""
    abs_dir = str(Path(directory).resolve())
    return abs_dir in _load_codex_trusts().get("trusted_directories", [])


def trust_directory(directory: str, target: str = "claude"):
    """Trust directory for Claude or Codex."""
    if target == "claude":
        abs_dir = str(Path(directory).resolve())
        settings: dict = {}
        if CLAUDE_JSON_PATH.exists():
            settings = json.loads(CLAUDE_JSON_PATH.read_text(encoding="utf-8"))

        projects = settings.setdefault("projects", {})
        proj = projects.setdefault(abs_dir, {})
        proj["hasTrustDialogAccepted"] = True

        CLAUDE_JSON_PATH.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        print(f"Trusted: {abs_dir}")
        return

    if target == "codex":
        abs_dir = _add_codex_trusted_directory(directory)
        print(f"Trusted for Codex: {abs_dir}")
        return

    raise ValueError(f"Unsupported trust target: {target}")


# ---------------------------------------------------------------------------
# Mode 3: tmux daemon (WSL/headless only)
# ---------------------------------------------------------------------------

# ANSI escape sequence pattern
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\x1b\[.*?[a-zA-Z]")

# Separator: 10+ consecutive box-drawing horizontal line characters
SEPARATOR_RE = re.compile(r"[─━]{10,}")

# Prompt detection patterns (below separator)
#
# Real Claude Code permission prompts look like:
#   "Do you want to proceed?"  /  "Do you want to allow Claude to fetch this content?"
#   ❯ 1. Yes
#     2. Yes, allow reading from User\ from this project
#     3. No
#   Esc to cancel · Tab to amend · ctrl+e to explain
#
# The ❯ cursor starts on option 1.  Option 2 = "allow for project/domain".

# Permission question line
PERMISSION_QUESTION_RE = re.compile(
    r"Do you want to (proceed|allow)",
    re.IGNORECASE,
)

# Numbered options with Yes/No (the actual selector lines)
NUMBERED_OPTION_RE = re.compile(
    r"^\s*[❯>]?\s*\d+\.\s*(Yes|No)",
    re.MULTILINE,
)

# Footer that confirms this is a real permission prompt
PERMISSION_FOOTER_RE = re.compile(
    r"Esc to cancel.*Tab to amend",
)

# Trust folder prompt
TRUST_RE = re.compile(
    r"(trust this|Trust this|trust folder|Trust folder|directory trusted)",
    re.IGNORECASE,
)

CODEX_STARTUP_TRUST_RE = re.compile(
    r"(Trust this directory|trust this directory|do you trust this directory|trust this repository|do you trust this repository)",
    re.IGNORECASE,
)

# "Continue?" prompt
CONTINUE_RE = re.compile(
    r"(Continue\?|Do you want to continue|Press Enter to continue)",
    re.IGNORECASE,
)

# Collapsed transcript indicator (Ctrl+O to expand)
COLLAPSED_RE = re.compile(
    r"(Ctrl\+O|ctrl\+o|collapsed|▶.*transcript|►.*transcript)",
    re.IGNORECASE,
)

# Slash command picker veto — 2+ lines matching "/command  description"
SLASH_PICKER_RE = re.compile(
    r"^\s*/\w+\s{2,}\S",
    re.MULTILINE,
)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return ANSI_RE.sub("", text)


def _extract_below_separator(text: str) -> str:
    """Extract text below the last separator line, or last 15 lines as fallback."""
    lines = text.splitlines()
    sep_idx = None
    for i in range(len(lines) - 1, -1, -1):
        if SEPARATOR_RE.search(lines[i]):
            sep_idx = i
            break
    if sep_idx is not None:
        return "\n".join(lines[sep_idx + 1:])
    return "\n".join(lines[-15:])


def count_options(text: str) -> int:
    """Count numbered options (1. Yes, 2. No, etc.) in prompt text."""
    return len(re.findall(r"^\s*[❯>]?\s*\d+\.\s+\S", text, re.MULTILINE))


def detect_prompt(text: str) -> tuple[str, int] | None:
    """Detect a prompt type in screen content.

    Returns (prompt_type, option_count) or None.

    Uses separator-anchored detection: finds last separator line,
    examines content below it.

    Real Claude Code prompts come in two variants:
      3-option: "Do you want to proceed?" → 1. Yes / 2. Yes, allow for project / 3. No
      2-option: "Do you want to proceed?" → 1. Yes / 2. No  (flagged commands)
    Footer: "Esc to cancel · Tab to amend · ctrl+e to explain"
    """
    below = _extract_below_separator(text)

    if not below.strip():
        return None

    # Veto: slash command picker
    slash_matches = SLASH_PICKER_RE.findall(below)
    if len(slash_matches) >= 2:
        return None

    # Primary detection: "Do you want to proceed/allow" + numbered options
    has_question = bool(PERMISSION_QUESTION_RE.search(below))
    has_numbered = bool(NUMBERED_OPTION_RE.search(below))
    has_footer = bool(PERMISSION_FOOTER_RE.search(below))

    if has_question and has_numbered:
        return ("permission", count_options(below))

    # Numbered options with footer but no question (partial render)
    if has_numbered and has_footer:
        return ("permission", count_options(below))

    if TRUST_RE.search(below):
        return ("trust", 0)

    if CONTINUE_RE.search(below):
        return ("continue", 0)

    return None


def detect_codex_startup_prompt(text: str) -> bool:
    """Detect Codex startup trust/setup prompts."""
    return bool(CODEX_STARTUP_TRUST_RE.search(text))


def detect_collapsed(text: str) -> bool:
    """Detect collapsed transcript that needs Ctrl+O to expand."""
    return bool(COLLAPSED_RE.search(text))


def _compile_completion_patterns(raw: str | None) -> list[re.Pattern[str]]:
    """Parse comma-separated regex completion patterns."""
    if not raw:
        return []
    patterns = []
    for item in raw.split(","):
        pattern = item.strip()
        if not pattern:
            continue
        patterns.append(re.compile(pattern))
    return patterns


class _CodexRunnerBackend:
    """Backend interface for interactive Codex sessions."""

    def readline(self) -> str:
        raise NotImplementedError

    def write(self, value: str) -> None:
        raise NotImplementedError

    def poll(self) -> int | None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def wait(self) -> int:
        raise NotImplementedError


class _SubprocessCodexBackend(_CodexRunnerBackend):
    """Codex backend backed by subprocess.Popen."""

    def __init__(self, proc: subprocess.Popen):
        self._proc = proc

    def readline(self) -> str:
        if self._proc.stdout is None:
            return ""
        return self._proc.stdout.readline()

    def write(self, value: str) -> None:
        if self._proc.stdin is None:
            return
        self._proc.stdin.write(value)
        self._proc.stdin.flush()

    def poll(self) -> int | None:
        return self._proc.poll()

    def close(self) -> None:
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        if self._proc.stdin is not None:
            self._proc.stdin.close()

    def wait(self) -> int:
        return self._proc.wait()


def _run_codex_process(
    backend: _CodexRunnerBackend,
    completion_patterns: list[re.Pattern[str]],
    working_directory: str | None = None,
) -> dict:
    """Run a Codex process with startup prompt handling and structured completion."""
    started = datetime.now(timezone.utc)
    startup_handled = False
    startup_prompt_seen = False
    completion_match: str | None = None
    output_length = 0

    while True:
        line = backend.readline()
        if line:
            print(line, end="", flush=True)
            output_length += len(line)
            if not startup_handled and detect_codex_startup_prompt(line):
                startup_prompt_seen = True
                startup_handled = True
                if working_directory and not _is_codex_trusted(working_directory):
                    _add_codex_trusted_directory(working_directory)
                backend.write("y\n")
                print("[agentnanny] auto-accepted Codex startup prompt", file=sys.stderr)
                continue
            for pattern in completion_patterns:
                if pattern.search(line):
                    completion_match = pattern.pattern
                    break
            continue

        if backend.poll() is not None:
            break
        time.sleep(0.05)

    ended = datetime.now(timezone.utc)
    exit_code = backend.poll()
    if exit_code is None:
        exit_code = -1

    completion_status = {
        "matched": completion_match is not None,
        "pattern": completion_match,
        "criteria_count": len(completion_patterns),
        "criteria": [p.pattern for p in completion_patterns],
    }

    return {
        "started_at": started.isoformat(timespec="seconds"),
        "ended_at": ended.isoformat(timespec="seconds"),
        "return_code": exit_code,
        "startup_prompt_seen": startup_prompt_seen,
        "completion": completion_status,
        "output_length": output_length,
    }


def run_codex_session(
    command_args: list[str],
    env: dict[str, str],
    completion: str | None = None,
    working_directory: str | None = None,
) -> dict:
    """Run a Codex command with startup prompt handling and structured result."""
    proc = subprocess.Popen(
        command_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=working_directory,
        env=env,
    )
    backend = _SubprocessCodexBackend(proc)
    try:
        completion_patterns = _compile_completion_patterns(completion)
        return _run_codex_process(
            backend,
            completion_patterns,
            working_directory=working_directory,
        )
    finally:
        backend.close()
        backend.wait()


class PaneState:
    """Per-pane state for cooldown tracking."""
    __slots__ = ("last_action_time", "last_content_hash")

    def __init__(self):
        self.last_action_time: float = 0.0
        self.last_content_hash: int = 0


class _InteractiveBackend:
    """Interactive prompt automation backend."""

    def list_targets(self, target: str | None = None) -> list[str]:
        raise NotImplementedError

    def capture(self, target: str) -> str:
        raise NotImplementedError

    def send_keys(self, target: str, keys: str) -> None:
        raise NotImplementedError


class _TmuxBackend(_InteractiveBackend):
    """tmux-backed prompt automation backend."""

    def __init__(self, session: str, dry_run: bool = False):
        self._session = session
        self._dry_run = dry_run

    def list_targets(self, target: str | None = None) -> list[str]:
        return tmux_list_panes(target or self._session)

    def capture(self, target: str) -> str:
        return tmux_capture(target)

    def send_keys(self, target: str, keys: str) -> None:
        tmux_send_keys(target, keys, dry_run=self._dry_run)


def tmux_capture(target: str) -> str:
    """Capture tmux pane content."""
    result = subprocess.run(
        ["tmux", "capture-pane", "-p", "-t", target],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        return ""
    return strip_ansi(result.stdout)


def tmux_send_keys(target: str, keys: str, dry_run: bool = False):
    """Send keys to a tmux pane."""
    if dry_run:
        return
    subprocess.run(
        ["tmux", "send-keys", "-t", target, keys],
        capture_output=True, timeout=5,
    )


def tmux_list_panes(session: str) -> list[str]:
    """List all pane targets in a tmux session."""
    result = subprocess.run(
        ["tmux", "list-panes", "-s", "-t", session, "-F", "#{pane_id}"],
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode != 0:
        return []
    return [p.strip() for p in result.stdout.strip().splitlines() if p.strip()]


def daemon_loop(session: str, cfg: dict):
    """Main polling loop for the tmux daemon."""
    daemon_cfg = cfg.get("daemon", {})
    poll_interval = float(daemon_cfg.get("poll_interval", 0.3))
    cooldown = float(daemon_cfg.get("cooldown_seconds", 2.0))
    dry_run = bool(daemon_cfg.get("dry_run", False))

    pane_states: dict[str, PaneState] = {}
    backend: _InteractiveBackend = _TmuxBackend(session, dry_run=dry_run)

    print(f"agentnanny daemon started — session={session} poll={poll_interval}s cooldown={cooldown}s dry_run={dry_run}")

    while True:
        panes = backend.list_targets()
        if not panes:
            time.sleep(poll_interval)
            continue

        now = time.monotonic()

        for pane in panes:
            state = pane_states.setdefault(pane, PaneState())

            # Cooldown check
            if now - state.last_action_time < cooldown:
                continue

            content = backend.capture(pane)
            if not content:
                continue

            content_hash = hash(content)
            if content_hash == state.last_content_hash:
                continue
            state.last_content_hash = content_hash

            # Check for collapsed transcript first
            if detect_collapsed(content):
                backend.send_keys(pane, "C-o")
                state.last_action_time = now
                audit_log("daemon", "expanded", "collapsed", f"pane={pane}", cfg)
                continue

            # Check for prompts
            result = detect_prompt(content)
            if result is None:
                continue

            prompt_type, num_options = result

            if prompt_type == "continue":
                backend.send_keys(pane, "Enter")
                state.last_action_time = now
                audit_log("daemon", "approved", "continue", f"pane={pane}", cfg)
            elif prompt_type == "trust":
                backend.send_keys(pane, "Enter")
                state.last_action_time = now
                audit_log("daemon", "approved", "trust", f"pane={pane}", cfg)
            elif prompt_type == "permission":
                if num_options >= 3:
                    # 3-option: 1. Yes / 2. Yes, allow for project / 3. No
                    # Cursor starts on 1. Down + Enter → option 2 (allow for project).
                    backend.send_keys(pane, "Down")
                    time.sleep(0.05)
                    backend.send_keys(pane, "Enter")
                    state.last_action_time = now
                    audit_log("daemon", "approved", "permission-opt2", f"pane={pane} opts={num_options}", cfg)
                else:
                    # 2-option: 1. Yes / 2. No (flagged commands)
                    # Cursor on 1. Enter → Yes.
                    backend.send_keys(pane, "Enter")
                    state.last_action_time = now
                    audit_log("daemon", "approved", "permission-opt1", f"pane={pane} opts={num_options}", cfg)

        time.sleep(poll_interval)


def start_daemon(session: str | None = None):
    """Start the tmux daemon."""
    cfg = load_config()
    session = session or cfg.get("daemon", {}).get("session", "claude")

    # Write PID file
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")

    def cleanup(signum, frame):
        PID_FILE.unlink(missing_ok=True)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    try:
        daemon_loop(session, cfg)
    finally:
        PID_FILE.unlink(missing_ok=True)


def stop_daemon():
    """Stop the tmux daemon."""
    if not PID_FILE.exists():
        print("No daemon running (no PID file)", file=sys.stderr)
        raise SystemExit(1)

    pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Stopped daemon (PID {pid})")
    except ProcessLookupError:
        print(f"Daemon (PID {pid}) not running, cleaning up PID file")
    PID_FILE.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def show_status():
    """Show hook installation status and daemon status."""
    # Hook status
    if SETTINGS_PATH.exists():
        settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        hooks = settings.get("hooks", {})
        perm = hooks.get("PermissionRequest", [])
        installed = any(
            HOOK_MARKER in h.get("command", "")
            for entry in perm
            for h in entry.get("hooks", [])
        )
        print(f"Hook installed: {'yes' if installed else 'no'}")
        print(f"Settings: {SETTINGS_PATH}")
    else:
        print("Hook installed: no (no settings file)")

    # Daemon status
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        try:
            os.kill(pid, 0)  # Check if process exists
            print(f"Daemon running: yes (PID {pid})")
        except (ProcessLookupError, PermissionError):
            print(f"Daemon running: no (stale PID file for {pid})")
    else:
        print("Daemon running: no")

    # Config
    cfg = load_config()
    deny = cfg.get("hooks", {}).get("deny", [])
    if deny:
        print(f"Deny list: {deny}")

    # Session scope
    scope_id = os.environ.get("AGENTNANNY_SCOPE")
    if scope_id:
        policy = load_session_policy(scope_id)
        if policy:
            groups = policy.get("allow_groups", [])
            tools = policy.get("allow_tools", [])
            ttl = policy.get("ttl_seconds", 0)
            created = policy.get("created", "?")
            print(f"Active scope: {scope_id} (created {created}, ttl={ttl}s)")
            if groups:
                print(f"  Groups: {', '.join(groups)}")
            if tools:
                print(f"  Tools: {', '.join(tools)}")
        else:
            print(f"Active scope: {scope_id} (expired or missing)")

    # All sessions
    policies = list_session_policies()
    if policies:
        print(f"Session policies: {len(policies)} active")

    # Codex status
    print()
    print("─── Codex CLI ───")
    if CODEX_CONFIG_PATH.exists():
        codex_text = CODEX_CONFIG_PATH.read_text(encoding="utf-8")
        codex_installed = HOOK_MARKER in codex_text
        print(f"Notify hook installed: {'yes' if codex_installed else 'no'}")
        print(f"Config: {CODEX_CONFIG_PATH}")
        # Parse approval_policy from config
        codex_cfg = parse_toml(codex_text)
        ap = codex_cfg.get("approval_policy")
        if ap:
            print(f"Approval policy: {ap}")
    else:
        print("Notify hook installed: no (no config file)")

    rules_dir = CODEX_HOME / "rules"
    if rules_dir.exists():
        rules_files = list(rules_dir.glob("agentnanny-*.rules"))
        if rules_files:
            print(f"Exec policy rules: {len(rules_files)} file(s)")


def show_log(
    lines_count: int = 50,
    output_format: str = "raw",
    filter_tool: str | None = None,
    filter_action: str | None = None,
) -> None:
    """Show the audit log with optional filtering and formatting."""
    cfg = load_config()
    log_path = cfg.get("logging", {}).get("audit_log", "/tmp/agentnanny.log")
    if not Path(log_path).exists():
        print(f"No log file at {log_path}")
        return
    with open(log_path, encoding="utf-8") as f:
        raw_lines = f.readlines()

    # Parse TSV lines into structured records
    records: list[dict[str, str]] = []
    for line in raw_lines:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        record = {
            "timestamp": parts[0],
            "source": parts[1],
            "action": parts[2],
            "tool_name": parts[3],
            "detail": parts[4],
        }
        if filter_tool and record["tool_name"] != filter_tool:
            continue
        if filter_action and record["action"] != filter_action:
            continue
        records.append(record)

    # Limit to last N records
    records = records[-lines_count:]

    if not records:
        print("No matching log entries.")
        return

    if output_format == "json":
        print(json.dumps(records, indent=2))
    elif output_format == "table":
        headers = ["TIMESTAMP", "SOURCE", "ACTION", "TOOL", "DETAIL"]
        keys = ["timestamp", "source", "action", "tool_name", "detail"]
        col_widths = [len(h) for h in headers]
        for rec in records:
            for i, key in enumerate(keys):
                col_widths[i] = max(col_widths[i], len(rec[key]))
        fmt = "  ".join(f"{{:<{w}}}" for w in col_widths)
        print(fmt.format(*headers))
        print(fmt.format(*("-" * w for w in col_widths)))
        for rec in records:
            print(fmt.format(*(rec[k] for k in keys)))
    else:
        # raw: original TSV lines
        for rec in records:
            print("\t".join(rec[k] for k in ["timestamp", "source", "action", "tool_name", "detail"]))


# ---------------------------------------------------------------------------
# Session commands
# ---------------------------------------------------------------------------


def _parse_ttl(ttl_str: str) -> int:
    """Parse a TTL string like '8h', '30m', '3600' into seconds."""
    ttl_str = ttl_str.strip().lower()
    if ttl_str.endswith("h"):
        return int(ttl_str[:-1]) * 3600
    if ttl_str.endswith("m"):
        return int(ttl_str[:-1]) * 60
    if ttl_str.endswith("s"):
        return int(ttl_str[:-1])
    return int(ttl_str)


def _build_policy(profile: str | None, groups: str | None, tools: str | None,
                  deny: str | None, ttl: str | None,
                  cfg: dict) -> tuple[dict, str]:
    """Build a session policy dict from CLI args. Returns (policy, scope_id)."""
    if profile:
        p = resolve_profile(profile, cfg)
        base_groups = p["groups"]
        base_deny = p["deny"]
        base_ttl = p["ttl"]
    else:
        base_groups = []
        base_deny = []
        base_ttl = "0"

    group_names = base_groups + ([g.strip() for g in groups.split(",")] if groups else [])
    tool_names = [t.strip() for t in tools.split(",")] if tools else []
    deny_patterns = base_deny + ([d.strip() for d in deny.split(",")] if deny else [])
    ttl_seconds = _parse_ttl(ttl if ttl is not None else base_ttl)

    if group_names:
        resolve_groups(group_names, cfg)

    for pat in deny_patterns:
        m_pat = re.match(r'^(\w+)\((.+)\)$', pat)
        if m_pat:
            try:
                re.compile(_glob_to_regex(m_pat.group(2)))
            except re.error as exc:
                raise ValueError(f"Invalid deny pattern {pat!r}: {exc}") from exc
        else:
            try:
                re.compile(pat)
            except re.error as exc:
                raise ValueError(f"Invalid deny pattern {pat!r}: {exc}") from exc

    scope_id = generate_scope_id()
    policy = {
        "scope_id": scope_id,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ttl_seconds": ttl_seconds,
        "allow_groups": group_names,
        "allow_tools": tool_names,
        "deny": deny_patterns,
    }
    if profile:
        policy["_profile_name"] = profile
    return policy, scope_id


def cmd_activate(profile: str | None, groups: str | None, tools: str | None,
                 deny: str | None, ttl: str | None, target: str = "claude"):
    """Create a session policy and print the env export command."""
    cfg = load_config()
    policy, scope_id = _build_policy(profile, groups, tools, deny, ttl, cfg)

    group_names = policy["allow_groups"]
    tool_names = policy["allow_tools"]
    deny_patterns = policy["deny"]
    ttl_seconds = policy["ttl_seconds"]

    path = save_session_policy(policy)
    print(f"export AGENTNANNY_SCOPE={scope_id}")
    print(f"# Policy: {path}", file=sys.stderr)
    if group_names:
        print(f"# Groups: {', '.join(group_names)}", file=sys.stderr)
    if tool_names:
        print(f"# Tools: {', '.join(tool_names)}", file=sys.stderr)
    if deny_patterns:
        print(f"# Deny: {', '.join(deny_patterns)}", file=sys.stderr)
    if ttl_seconds:
        print(f"# TTL: {ttl_seconds}s", file=sys.stderr)

    if target == "codex":
        _apply_codex_session(policy, cfg, scope_id)


def cmd_extend(scope_id: str | None, groups: str | None, tools: str | None,
               deny: str | None):
    """Add groups, tools, or deny patterns to an existing session policy."""
    scope_id = scope_id or os.environ.get("AGENTNANNY_SCOPE")
    if not scope_id:
        print("No scope ID provided and AGENTNANNY_SCOPE not set", file=sys.stderr)
        raise SystemExit(1)
    if not _valid_scope_id(scope_id):
        print(f"Invalid scope ID: {scope_id}", file=sys.stderr)
        raise SystemExit(1)

    policy = load_session_policy(scope_id)
    if policy is None:
        print(f"No active session policy found for {scope_id}", file=sys.stderr)
        raise SystemExit(1)

    cfg = load_config()

    # Parse new values
    new_groups = [g.strip() for g in groups.split(",")] if groups else []
    new_tools = [t.strip() for t in tools.split(",")] if tools else []
    new_deny = [d.strip() for d in deny.split(",")] if deny else []

    # Validate new groups
    if new_groups:
        resolve_groups(new_groups, cfg)

    # Merge with deduplication
    existing_groups = policy.get("allow_groups", [])
    existing_tools = policy.get("allow_tools", [])
    existing_deny = policy.get("deny", [])

    for g in new_groups:
        if g not in existing_groups:
            existing_groups.append(g)
    for t in new_tools:
        if t not in existing_tools:
            existing_tools.append(t)
    for d in new_deny:
        if d not in existing_deny:
            existing_deny.append(d)

    policy["allow_groups"] = existing_groups
    policy["allow_tools"] = existing_tools
    policy["deny"] = existing_deny

    save_session_policy(policy)

    print(f"# Extended session {scope_id}", file=sys.stderr)
    if new_groups:
        print(f"# Added groups: {', '.join(new_groups)}", file=sys.stderr)
    if new_tools:
        print(f"# Added tools: {', '.join(new_tools)}", file=sys.stderr)
    if new_deny:
        print(f"# Added deny: {', '.join(new_deny)}", file=sys.stderr)
    print(f"# Groups: {', '.join(existing_groups)}", file=sys.stderr)
    print(f"# Tools: {', '.join(existing_tools)}", file=sys.stderr)
    print(f"# Deny: {', '.join(existing_deny)}", file=sys.stderr)


def cmd_deactivate(scope_id: str | None, target: str = "claude"):
    """Remove a session policy."""
    scope_id = scope_id or os.environ.get("AGENTNANNY_SCOPE")
    if not scope_id:
        print("No scope ID provided and AGENTNANNY_SCOPE not set", file=sys.stderr)
        raise SystemExit(1)
    if not _valid_scope_id(scope_id):
        print(f"Invalid scope ID: {scope_id}", file=sys.stderr)
        raise SystemExit(1)
    if delete_session_policy(scope_id):
        print(f"unset AGENTNANNY_SCOPE")
        print(f"# Removed session {scope_id}", file=sys.stderr)
        if target == "codex":
            _remove_codex_session(scope_id)
            print("# Removed Codex exec policy rules", file=sys.stderr)
    else:
        print(f"No session policy found for {scope_id}", file=sys.stderr)
        raise SystemExit(1)


def cmd_run(profile: str | None, groups: str | None, tools: str | None,
            deny: str | None, ttl: str | None, command_args: list[str],
            completion: str | None = None, target: str = "claude"):
    """Run a command with session-scoped permissions."""
    if not command_args:
        print("No command specified", file=sys.stderr)
        raise SystemExit(1)
    if command_args and command_args[0] == "--":
        command_args = command_args[1:]
    if not command_args:
        print("No command specified after --", file=sys.stderr)
        raise SystemExit(1)

    cfg = load_config()
    policy, scope_id = _build_policy(profile, groups, tools, deny, ttl, cfg)
    save_session_policy(policy)

    env = os.environ.copy()
    env["AGENTNANNY_SCOPE"] = scope_id

    if target == "codex":
        _apply_codex_session(policy, cfg, scope_id)

    try:
        if target == "codex":
            result = run_codex_session(
                command_args,
                env,
                completion=completion,
                working_directory=str(Path.cwd()),
            )
            if completion is not None:
                print(json.dumps(result))
            raise SystemExit(result["return_code"])

        result = subprocess.run(command_args, env=env)
        raise SystemExit(result.returncode)
    finally:
        delete_session_policy(scope_id)
        if target == "codex":
            _remove_codex_session(scope_id)


PROJECT_CONFIG_TEMPLATE = """\
# agentnanny project config
# This file is loaded automatically when working in this directory.
# It merges on top of user config and built-in defaults.

[hooks]
# Project-specific deny patterns (in addition to global deny)
# deny = ["Bash(terraform destroy*)", "Bash(aws iam delete*)"]

# ── Custom groups for this project ──────────────────────────
# [groups]
# project-tools = ["Bash(make*)", "Bash(cargo*)", "Bash(go test*)"]

# ── Custom profiles for this project ────────────────────────
# [profiles.project-dev]
# groups = ["filesystem", "shell", "project-tools"]
# deny = []
# ttl = "8h"
"""


def cmd_init():
    """Create a .agentnanny.toml in the current directory."""
    target = Path.cwd() / ".agentnanny.toml"
    if target.exists():
        print(f"Already exists: {target}", file=sys.stderr)
        raise SystemExit(1)
    target.write_text(PROJECT_CONFIG_TEMPLATE, encoding="utf-8")
    print(f"Created {target}")


def cmd_list_groups():
    """List all configured groups (builtin + config)."""
    cfg = load_config()
    groups = cfg.get("groups", {})
    if not groups:
        print("No groups configured")
        return
    max_name = max(len(n) for n in groups)
    for name in sorted(groups):
        patterns = ", ".join(groups[name])
        print(f"  {name:<{max_name}}  {patterns}")


def cmd_explain(scope_id: str | None):
    """Inspect a session policy in detail."""
    if scope_id is None:
        scope_id = os.environ.get("AGENTNANNY_SCOPE")
    if not scope_id:
        print("No scope ID provided and AGENTNANNY_SCOPE not set", file=sys.stderr)
        raise SystemExit(1)
    if not _valid_scope_id(scope_id):
        print(f"Invalid scope ID: {scope_id}", file=sys.stderr)
        raise SystemExit(1)

    policy = load_session_policy(scope_id)
    if policy is None:
        print(f"No active session for scope: {scope_id}", file=sys.stderr)
        raise SystemExit(1)

    cfg = load_config()
    created = datetime.fromisoformat(policy["created"])
    ttl = policy.get("ttl_seconds", 0)
    groups = policy.get("allow_groups", [])
    tools = policy.get("allow_tools", [])
    deny = policy.get("deny", [])

    print(f"Session: {scope_id}")
    print(f"Created: {policy['created']}")

    if ttl:
        elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        remaining = max(0, int(ttl - elapsed))
        print(f"TTL: {ttl}s ({remaining}s remaining)")
    else:
        print("TTL: none")

    groups_str = ", ".join(groups) if groups else "-"
    tools_str = ", ".join(tools) if tools else "-"
    deny_str = ", ".join(deny) if deny else "-"

    print(f"Groups: {groups_str}")
    if groups:
        groups_cfg = cfg.get("groups", {})
        for g in groups:
            patterns = groups_cfg.get(g, [])
            print(f"  {g} -> {', '.join(patterns)}")
    print(f"Tools: {tools_str}")
    print(f"Deny: {deny_str}")


def cmd_list_profiles():
    """List all available profiles (builtin + config)."""
    cfg = load_config()
    profiles = cfg.get("profiles", {})
    if not profiles:
        print("No profiles configured")
        return
    for name in sorted(profiles):
        p = profiles[name]
        groups = ", ".join(p.get("groups", []))
        deny_count = len(p.get("deny", []))
        ttl = p.get("ttl", "0")
        source = "builtin" if name in BUILTIN_PROFILES else "config"
        deny_str = f"  deny={deny_count}" if deny_count else ""
        print(f"  {name:<14} groups=[{groups}]  ttl={ttl}{deny_str}  ({source})")


def cmd_sessions():
    """List active session policies."""
    policies = list_session_policies()
    if not policies:
        print("No active sessions")
        return
    now = datetime.now(timezone.utc)
    for p in policies:
        scope_id = p["scope_id"]
        created = datetime.fromisoformat(p["created"])
        age = int((now - created).total_seconds())
        ttl = p.get("ttl_seconds", 0)
        groups = ", ".join(p.get("allow_groups", [])) or "-"
        tools = ", ".join(p.get("allow_tools", [])) or "-"
        ttl_str = f"{ttl - age}s remaining" if ttl else "no expiry"
        print(f"{scope_id}  age={age}s  {ttl_str}  groups=[{groups}]  tools=[{tools}]")


def cmd_prune():
    """Remove expired session policy files."""
    if not SESSION_DIR.exists():
        print("No sessions directory")
        return
    now = datetime.now(timezone.utc)
    removed = 0
    for path in SESSION_DIR.glob("*.json"):
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            path.unlink(missing_ok=True)
            removed += 1
            continue
        ttl = policy.get("ttl_seconds", 0)
        if ttl > 0:
            created = datetime.fromisoformat(policy["created"])
            elapsed = (now - created).total_seconds()
            if elapsed > ttl:
                path.unlink(missing_ok=True)
                removed += 1
    print(f"Pruned {removed} expired session(s)")


# ---------------------------------------------------------------------------
# Dry-run policy evaluation
# ---------------------------------------------------------------------------


def evaluate_policy(
    tool_name: str, tool_input: dict, cfg: dict, scope_id: str | None = None,
) -> tuple[str, str]:
    """Evaluate a tool call against the current policy without side effects.

    Returns (verdict, reason) where verdict is one of:
    - "deny" — blocked by global or session deny list
    - "allow" — explicitly allowed by session policy
    - "passthrough" — not covered, would show normal permission dialog
    """
    global_deny = cfg.get("hooks", {}).get("deny", [])

    # Global deny always applies
    if matches_deny(tool_name, tool_input, global_deny):
        return ("deny", f"blocked by global deny list")

    if not scope_id:
        # Legacy mode — check config allow list
        allow_list = cfg.get("hooks", {}).get("allow", None)
        if allow_list is None:
            return ("passthrough", "no scope and no allow list configured")
        if tool_name in allow_list:
            return ("allow", f"{tool_name} in legacy allow list")
        return ("deny", f"{tool_name} not in legacy allow list")

    # Session-scoped mode
    policy = load_session_policy(scope_id)
    if policy is None:
        return ("passthrough", f"no valid session policy for scope {scope_id}")

    # Session-level deny
    session_deny = policy.get("deny", [])
    if session_deny and matches_deny(tool_name, tool_input, session_deny):
        return ("deny", f"blocked by session deny list (scope {scope_id})")

    # Resolve session allow list
    allow_patterns: list[str] = list(policy.get("allow_tools", []))
    group_names = policy.get("allow_groups", [])
    if group_names:
        try:
            allow_patterns.extend(resolve_groups(group_names, cfg))
        except ValueError as exc:
            return ("passthrough", f"group resolution failed: {exc}")

    if matches_allow(tool_name, tool_input, allow_patterns):
        return ("allow", f"{tool_name} allowed by session policy (scope {scope_id})")

    return ("passthrough", f"{tool_name} not in session allow list (scope {scope_id})")


def cmd_test_policy(tool_name: str, tool_input_json: str, scope: str | None):
    """CLI wrapper for evaluate_policy."""
    tool_input = json.loads(tool_input_json)
    cfg = load_config()
    scope_id = scope or os.environ.get("AGENTNANNY_SCOPE")
    verdict, reason = evaluate_policy(tool_name, tool_input, cfg, scope_id)
    print(f"{verdict}: {reason}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        prog="agentnanny",
        description="Granular permission manager for Claude Code and Codex CLI.",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("hook", help="Hook handler (called by Claude Code, not user)")
    sub.add_parser("post-hook", help="PostToolUse hook handler (called by Claude Code, not user)")
    sub.add_parser("codex-hook", help="Notify handler (called by Codex CLI, not user)")

    p_install = sub.add_parser("install", help="Register hooks in agent config")
    p_install.add_argument("--target", choices=TARGETS, default="claude",
                           help="Target agent (default: claude)")
    p_uninstall = sub.add_parser("uninstall", help="Remove hooks from agent config")
    p_uninstall.add_argument("--target", choices=TARGETS, default="claude",
                             help="Target agent (default: claude)")

    p_trust = sub.add_parser("trust", help="Pre-trust a directory")
    p_trust.add_argument("directory", nargs="?", default=".", help="Directory to trust (default: .)")
    p_trust.add_argument("--target", choices=TARGETS, default="claude", help="Target agent (default: claude)")

    p_watch = sub.add_parser("watch", help="Start tmux daemon (WSL only)")
    p_watch.add_argument("session", nargs="?", help="tmux session name")

    sub.add_parser("stop", help="Stop tmux daemon")
    sub.add_parser("init", help="Create .agentnanny.toml in current directory")
    sub.add_parser("status", help="Show hook + daemon status")
    p_log = sub.add_parser("log", help="Tail audit log")
    p_log.add_argument("--lines", "-n", type=int, default=50, help="Number of lines to show (default: 50)")
    p_log.add_argument("--format", "-f", dest="log_format", choices=["raw", "json", "table"], default="raw", help="Output format (default: raw)")
    p_log.add_argument("--tool", default=None, help="Filter by tool name")
    p_log.add_argument("--action", default=None, help="Filter by action")

    p_activate = sub.add_parser("activate", help="Create a session policy (prints export command)")
    p_activate.add_argument("profile", nargs="?", default=None, help="Profile name (e.g. safe-dev)")
    p_activate.add_argument("--groups", "-g", default=None, help="Comma-separated group names")
    p_activate.add_argument("--tools", "-t", default=None, help="Comma-separated tool names")
    p_activate.add_argument("--deny", "-d", default=None, help="Comma-separated deny patterns")
    p_activate.add_argument("--ttl", default=None, help="TTL (e.g. 8h, 30m, 3600)")
    p_activate.add_argument("--target", choices=TARGETS, default="claude",
                            help="Target agent (default: claude)")

    p_deactivate = sub.add_parser("deactivate", help="Remove a session policy")
    p_deactivate.add_argument("scope_id", nargs="?", default=None, help="Scope ID (default: from AGENTNANNY_SCOPE)")
    p_deactivate.add_argument("--target", choices=TARGETS, default="claude",
                              help="Target agent (default: claude)")

    p_extend = sub.add_parser("extend", help="Add groups, tools, or deny patterns to an existing session")
    p_extend.add_argument("scope_id", nargs="?", default=None, help="Scope ID (default: from AGENTNANNY_SCOPE)")
    p_extend.add_argument("--groups", "-g", default=None, help="Comma-separated group names to add")
    p_extend.add_argument("--tools", "-t", default=None, help="Comma-separated tool names to add")
    p_extend.add_argument("--deny", "-d", default=None, help="Comma-separated deny patterns to add")

    p_run = sub.add_parser("run", help="Run command with session-scoped permissions")
    p_run.add_argument("profile", nargs="?", default=None, help="Profile name (e.g. safe-dev)")
    p_run.add_argument("--groups", "-g", default=None, help="Comma-separated group names")
    p_run.add_argument("--tools", "-t", default=None, help="Comma-separated tool names")
    p_run.add_argument("--deny", "-d", default=None, help="Comma-separated deny patterns")
    p_run.add_argument("--ttl", default=None, help="TTL (e.g. 8h, 30m, 3600)")
    p_run.add_argument("--target", choices=TARGETS, default="claude",
                        help="Target agent (default: claude)")
    p_run.add_argument("--completion", default=None,
                       help="Comma-separated regex criteria for Codex completion")
    p_run.add_argument("command_args", nargs=argparse.REMAINDER, help="Command to run (after --)")

    sub.add_parser("profiles", help="List available profiles")
    sub.add_parser("sessions", help="List active session policies")
    sub.add_parser("prune", help="Remove expired session files")
    sub.add_parser("list-groups", help="List all configured groups")

    p_explain = sub.add_parser("explain", help="Inspect a session policy in detail")
    p_explain.add_argument("scope_id", nargs="?", default=None, help="Scope ID (default: from AGENTNANNY_SCOPE)")

    p_test = sub.add_parser("test-policy", help="Dry-run policy evaluation")
    p_test.add_argument("tool_name", help="Tool name to evaluate (e.g. Bash, Write)")
    p_test.add_argument("--input", "-i", default="{}", dest="tool_input", help="JSON string for tool_input (default: {})")
    p_test.add_argument("--scope", "-s", default=None, help="Scope ID (default: from AGENTNANNY_SCOPE)")

    args = parser.parse_args()

    if args.command == "hook":
        handle_hook()
    elif args.command == "post-hook":
        handle_post_hook()
    elif args.command == "codex-hook":
        handle_codex_hook()
    elif args.command == "install":
        if args.target == "codex":
            install_codex_hooks()
        else:
            install_hooks()
    elif args.command == "uninstall":
        if args.target == "codex":
            uninstall_codex_hooks()
        else:
            uninstall_hooks()
    elif args.command == "trust":
        trust_directory(args.directory, args.target)
    elif args.command == "watch":
        start_daemon(args.session)
    elif args.command == "stop":
        stop_daemon()
    elif args.command == "init":
        cmd_init()
    elif args.command == "status":
        show_status()
    elif args.command == "log":
        show_log(
            lines_count=args.lines,
            output_format=args.log_format,
            filter_tool=args.tool,
            filter_action=args.action,
        )
    elif args.command == "activate":
        cmd_activate(args.profile, args.groups, args.tools, args.deny, args.ttl, args.target)
    elif args.command == "deactivate":
        cmd_deactivate(args.scope_id, args.target)
    elif args.command == "extend":
        cmd_extend(args.scope_id, args.groups, args.tools, args.deny)
    elif args.command == "run":
        cmd_run(
            args.profile,
            args.groups,
            args.tools,
            args.deny,
            args.ttl,
            args.command_args,
            args.completion,
            args.target,
        )
    elif args.command == "profiles":
        cmd_list_profiles()
    elif args.command == "sessions":
        cmd_sessions()
    elif args.command == "prune":
        cmd_prune()
    elif args.command == "list-groups":
        cmd_list_groups()
    elif args.command == "explain":
        cmd_explain(args.scope_id)
    elif args.command == "test-policy":
        cmd_test_policy(args.tool_name, args.tool_input, args.scope)
    else:
        parser.print_help()
        raise SystemExit(1)


if __name__ == "__main__":
    main()

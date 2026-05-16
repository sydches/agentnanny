"""Tests for agentnanny — hook handler, deny matching, install/uninstall, tmux detection."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent))
import agentnanny


# ═══════════════════════════════════════════════════════════════════════════
# TOML parser
# ═══════════════════════════════════════════════════════════════════════════


class TestParseToml:
    def test_basic_table(self):
        text = '[hooks]\ndeny = ["Bash", "Write"]'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == ["Bash", "Write"]

    def test_string_value(self):
        text = '[daemon]\nsession = "claude"'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["session"] == "claude"

    def test_bool_values(self):
        text = '[daemon]\ndry_run = false'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["dry_run"] is False

    def test_float_value(self):
        text = '[daemon]\npoll_interval = 0.3'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["poll_interval"] == 0.3

    def test_int_value(self):
        text = '[daemon]\nretries = 3'
        result = agentnanny.parse_toml(text)
        assert result["daemon"]["retries"] == 3

    def test_empty_array(self):
        text = '[hooks]\ndeny = []'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == []

    def test_comments_ignored(self):
        text = '# comment\n[hooks]\n# another comment\ndeny = []'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == []

    def test_multiple_tables(self):
        text = '[hooks]\ndeny = []\n[daemon]\nsession = "claude"\n[logging]\nlevel = "actions"'
        result = agentnanny.parse_toml(text)
        assert result["hooks"]["deny"] == []
        assert result["daemon"]["session"] == "claude"
        assert result["logging"]["level"] == "actions"


# ═══════════════════════════════════════════════════════════════════════════
# Deny-list matching
# ═══════════════════════════════════════════════════════════════════════════


class TestMatchesDeny:
    def test_exact_tool_name(self):
        assert agentnanny.matches_deny("Bash", {}, ["Bash"]) is True

    def test_exact_tool_name_no_match(self):
        assert agentnanny.matches_deny("Read", {}, ["Bash"]) is False

    def test_tool_with_input_pattern(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "rm -rf /"}, ["Bash(rm*)"]
        ) is True

    def test_tool_with_input_pattern_no_match(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "ls -la"}, ["Bash(rm*)"]
        ) is False

    def test_tool_input_exact_prefix(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "rm -rf /tmp"}, ["Bash(rm -rf*)"]
        ) is True

    def test_tool_input_no_match_different_tool(self):
        assert agentnanny.matches_deny(
            "Read", {"file_path": "/etc/passwd"}, ["Bash(rm*)"]
        ) is False

    def test_regex_pattern(self):
        assert agentnanny.matches_deny("WebFetch", {}, [".*Fetch.*"]) is True

    def test_regex_no_match(self):
        assert agentnanny.matches_deny("Read", {}, [".*Fetch.*"]) is False

    def test_empty_deny_list(self):
        assert agentnanny.matches_deny("Bash", {"command": "rm -rf /"}, []) is False

    def test_multiple_patterns(self):
        deny = ["Bash(rm*)", "Bash(dd*)", "WebFetch"]
        assert agentnanny.matches_deny("Bash", {"command": "rm /tmp/x"}, deny) is True
        assert agentnanny.matches_deny("Bash", {"command": "dd if=/dev/zero"}, deny) is True
        assert agentnanny.matches_deny("WebFetch", {"url": "http://x"}, deny) is True
        assert agentnanny.matches_deny("Bash", {"command": "ls"}, deny) is False

    def test_write_file_path_pattern(self):
        assert agentnanny.matches_deny(
            "Write", {"file_path": "/etc/passwd"}, ["Write(/etc/*)"]
        ) is True

    def test_webfetch_url_pattern(self):
        assert agentnanny.matches_deny(
            "WebFetch", {"url": "https://evil.com/payload"}, ["WebFetch(*evil.com*)"]
        ) is True


# ═══════════════════════════════════════════════════════════════════════════
# Primary input extraction
# ═══════════════════════════════════════════════════════════════════════════


class TestPrimaryInput:
    def test_bash(self):
        assert agentnanny._primary_input("Bash", {"command": "ls"}) == "ls"

    def test_write(self):
        assert agentnanny._primary_input("Write", {"file_path": "/tmp/x"}) == "/tmp/x"

    def test_edit(self):
        assert agentnanny._primary_input("Edit", {"file_path": "/tmp/x"}) == "/tmp/x"

    def test_read(self):
        assert agentnanny._primary_input("Read", {"file_path": "/tmp/x"}) == "/tmp/x"

    def test_webfetch(self):
        assert agentnanny._primary_input("WebFetch", {"url": "http://x"}) == "http://x"

    def test_unknown_tool(self):
        result = agentnanny._primary_input("Custom", {"a": "1", "b": "2"})
        assert "1" in result and "2" in result


# ═══════════════════════════════════════════════════════════════════════════
# Hook handler
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleHook:
    def _run_hook(self, event: dict, deny: list[str] | None = None,
                  allow: list[str] | None = None) -> dict | None:
        """Run handle_hook with mocked stdin/stdout/config.

        Returns parsed JSON decision, or None for passthrough (empty output).
        """
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}
        if deny:
            cfg["hooks"]["deny"] = deny
        if allow is not None:
            cfg["hooks"]["allow"] = allow

        stdin = StringIO(json.dumps(event))
        stdout = StringIO()

        with patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.handle_hook()

        raw = stdout.getvalue()
        if not raw:
            return None
        return json.loads(raw)

    def test_passthrough_no_scope_no_allow(self):
        """Without scope or allow list, hook passes through (no output)."""
        result = self._run_hook({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        assert result is None

    def test_passthrough_read_no_scope(self):
        """Read tool also passes through when no scope is active."""
        result = self._run_hook({
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.py"},
        })
        assert result is None

    def test_deny_by_tool_name(self):
        result = self._run_hook(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            deny=["WebFetch"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_deny_by_command_pattern(self):
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            deny=["Bash(rm*)"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_passthrough_when_not_denied_no_scope(self):
        """Tool not in deny list but no scope/allow → passthrough."""
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            deny=["Bash(rm*)"],
        )
        assert result is None

    def test_allow_list_permits(self):
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            allow=["Bash", "Read"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_allow_list_blocks(self):
        result = self._run_hook(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            allow=["Bash", "Read"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_deny_takes_priority_over_allow(self):
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            deny=["Bash(rm*)"],
            allow=["Bash"],
        )
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_output_structure(self):
        """With explicit allow list, output has correct JSON structure."""
        result = self._run_hook(
            {"tool_name": "Bash", "tool_input": {"command": "echo hi"}},
            allow=["Bash"],
        )
        assert "hookSpecificOutput" in result
        assert "hookEventName" in result["hookSpecificOutput"]
        assert result["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
        assert "decision" in result["hookSpecificOutput"]
        assert "behavior" in result["hookSpecificOutput"]["decision"]

    def test_missing_tool_name(self):
        """Missing tool_name with no scope → passthrough."""
        result = self._run_hook({"tool_input": {"command": "ls"}})
        assert result is None

    def test_missing_tool_input(self):
        """Missing tool_input with no scope → passthrough."""
        result = self._run_hook({"tool_name": "Bash"})
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# ANSI stripping
# ═══════════════════════════════════════════════════════════════════════════


class TestStripAnsi:
    def test_no_ansi(self):
        assert agentnanny.strip_ansi("hello world") == "hello world"

    def test_color_codes(self):
        assert agentnanny.strip_ansi("\x1b[31mred\x1b[0m") == "red"

    def test_bold(self):
        assert agentnanny.strip_ansi("\x1b[1mbold\x1b[0m") == "bold"

    def test_cursor_movement(self):
        assert agentnanny.strip_ansi("\x1b[2Aup two\x1b[1Bdown one") == "up twodown one"

    def test_mixed_sequences(self):
        text = "\x1b[32m✓\x1b[0m \x1b[1mDone\x1b[0m"
        assert agentnanny.strip_ansi(text) == "✓ Done"

    def test_osc_sequences(self):
        text = "\x1b]0;title\x07content"
        assert agentnanny.strip_ansi(text) == "content"

    def test_empty_string(self):
        assert agentnanny.strip_ansi("") == ""

    def test_complex_real_world(self):
        text = "\x1b[38;5;208m● \x1b[0m\x1b[1mAllow \x1b[0m\x1b[2mBash\x1b[0m"
        result = agentnanny.strip_ansi(text)
        assert "Allow" in result
        assert "Bash" in result
        assert "\x1b" not in result


# ═══════════════════════════════════════════════════════════════════════════
# Prompt detection
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectPrompt:
    r"""Tests based on real Claude Code permission prompt screenshots.

    3-option (normal):
        Do you want to proceed?
        > 1. Yes
          2. Yes, allow reading from User\ from this project
          3. No
        Esc to cancel . Tab to amend . ctrl+e to explain

    3-option (fetch):
        Do you want to allow Claude to fetch this content?
        > 1. Yes
          2. Yes, and don't ask again for docs.anthropic.com
          3. No, and tell Claude what to do differently (esc)

    2-option (flagged command — shell operators, $(), quoted flags):
        Command contains a backslash before a shell operator (;, |, &, <, >)
        Do you want to proceed?
        > 1. Yes
          2. No
        Esc to cancel . Tab to amend . ctrl+e to explain
    """

    def _make_screen(self, above: str, below: str) -> str:
        sep = "─" * 40
        return f"{above}\n{sep}\n{below}"

    # ── 3-option prompts (normal) ──────────────────────────────────────

    def test_bash_3opt(self):
        screen = self._make_screen(
            "Bash command\n"
            "    cat ~/.claude.json\n"
            "    Check existing .claude.json",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, allow reading from User\\\\ from this project\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_fetch_3opt(self):
        screen = self._make_screen(
            "Fetch\n"
            "    https://docs.anthropic.com/en/docs/claude-code/hooks\n"
            "    Claude wants to fetch content from docs.anthropic.com",
            "Do you want to allow Claude to fetch this content?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don't ask again for docs.anthropic.com\n"
            "  3. No, and tell Claude what to do differently (esc)",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_write_3opt(self):
        screen = self._make_screen(
            "Write\n    /tmp/test.py\n    Create test file",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, allow writing to this project\n"
            "  3. No",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_3opt_partial_render(self):
        """Numbered options + footer but question scrolled off."""
        screen = self._make_screen(
            "Some output",
            "❯ 1. Yes\n"
            "  2. Yes, allow for this project\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_3opt_cursor_on_opt2(self):
        """Cursor moved to option 2 before daemon acts."""
        screen = self._make_screen(
            "Bash command\n    ls -la",
            "Do you want to proceed?\n"
            "  1. Yes\n"
            "❯ 2. Yes, allow reading from this project\n"
            "  3. No",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    # ── 2-option prompts (flagged commands) ────────────────────────────

    def test_bash_2opt_backslash_shell_operator(self):
        """From screenshot: backslash before shell operator warning."""
        screen = self._make_screen(
            "Bash command\n"
            "    find /home -name \"checkpoint.json\" -exec sh -c 'echo \"---\"' \\;\n"
            "    Summarize all checkpoint statuses\n"
            "\n"
            "Command contains a backslash before a shell operator (;, |, &, <, >) "
            "which can hide command structure",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_command_substitution(self):
        """From screenshot: $() command substitution warning."""
        screen = self._make_screen(
            "Bash command\n"
            "    for repo in /home/user/repos/*/; do bytes=$(git -C \"$repo\" diff | wc -c); done\n"
            "    Check which repos have diffs and sizes\n"
            "\n"
            "Command contains $() command substitution",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_quoted_flags(self):
        """From screenshot: quoted characters in flag names warning."""
        screen = self._make_screen(
            "Bash command\n"
            "    ls -la /home/user/results/; echo \"---\"; for repo in /repos/*/; do done\n"
            "    Check run dir contents and repo diffs\n"
            "\n"
            "Command contains quoted characters in flag names",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_no_warning(self):
        """2-option prompt without a warning line (plain dangerous command)."""
        screen = self._make_screen(
            "Bash command\n"
            "    cat /home/user/results/checkpoint.json | jq '.key'\n"
            "    Check checkpoint and patches for featurebench run",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    # ── 2-option prompts (more warning variants from screenshots) ─────

    def test_bash_2opt_variables_dangerous_contexts(self):
        """From screenshot: variables in dangerous contexts (redirections or pipes)."""
        screen = self._make_screen(
            "Bash command\n"
            "    for info in with_feature/20260303_131030:starter_tasks ...; do\n"
            "    python3 -c \"import json; ...\" 2>/dev/null\n"
            "    Check earlier complete runs",
            "Command contains variables in dangerous contexts (redirections or pipes)\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_newlines_separate_commands(self):
        """From screenshot: newlines that could separate multiple commands."""
        screen = self._make_screen(
            "Bash command\n"
            "    # Check the 213* set (most recent 6 invocations)\n"
            "    for d in 20260303_213418 20260303_213419 ...; do\n"
            "      found=\"\"\n"
            "      for arm in wo_feature with_feature; do\n"
            "        p=\"/home/user/projects/example/results/$arm/$d\"\n"
            "      done\n"
            "    done\n"
            "    Check latest 6 invocations (213* set)",
            "Command contains newlines that could separate multiple commands\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_ambiguous_command_separators(self):
        """From screenshot: ambiguous syntax with command separators."""
        screen = self._make_screen(
            "Bash command\n"
            "    for d in /home/user/projects/example/results/*/2026*/; do "
            "if [ -f \"$d/config.json\" ]; then echo \"=== $d ===\"; "
            "cat \"$d/config.json\" 2>/dev/null; echo; fi; done\n"
            "    Show config.json for all runs",
            "Command contains ambiguous syntax with command separators "
            "that could be misinterpreted\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    def test_bash_2opt_cd_git_compound(self):
        """From screenshot: compound commands with cd and git."""
        screen = self._make_screen(
            "Bash command\n"
            "    cd /home/user/projects/example/results/with_feature/20260303_214027"
            "/repos/pydata__xarray && git diff 2>/dev/null\n"
            "    Get pydata__xarray patch (correct dir)",
            "Compound commands with cd and git require approval "
            "to prevent bare repository attacks\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    # ── 3-option prompt variant (tool prefix pattern) ─────────────────

    def test_bash_3opt_dont_ask_again_tool_prefix(self):
        """From screenshot: 'don't ask again for: python3:*' option."""
        screen = self._make_screen(
            "Bash command\n"
            "    echo \"=== with_feature benchmark (214009) ===\" && python3 -c \"\n"
            "    import json\n"
            "    cp = json.load(open('results/with_feature/20260303_214009/checkpoint.json'))\n"
            "    for k,v in cp.items(): print(f'{k}: {v.get(\"status\",\"?\")}')\"\n"
            "    Check checkpoint status for main 10-task runs",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don't ask again for: python3:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    # ── 2-option prompt variant (Zsh glob qualifier warning) ──────────

    def test_bash_2opt_zsh_glob_qualifier(self):
        """From screenshot: Zsh glob qualifier with command execution."""
        screen = self._make_screen(
            "Bash command\n"
            "    .venv/Scripts/python.exe benchmark.py\n"
            "    Benchmark 10 then 100 images with per-phase timing",
            "Command contains Zsh glob qualifier with command execution\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 2)

    # ── 3-option prompt variant (generic approval + don't ask again) ──

    def test_bash_3opt_this_command_requires_approval(self):
        """From screenshot: taskkill with 'This command requires approval'."""
        screen = self._make_screen(
            "Bash command\n"
            "\n"
            "    taskkill //PID 19152 //F\n"
            "    Kill the embedding process",
            "This command requires approval\n"
            "\n"
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don't ask again for: taskkill:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_bash_3opt_dont_ask_again_windows_venv(self):
        """From screenshot: Windows .venv python with backslash-containing path."""
        screen = self._make_screen(
            "Bash command\n"
            "\n"
            "    cd /d/ppt/OracleAI && .venv/Scripts/python.exe -c "
            "\"from qdrant_client import QdrantClient; print('qdrant_client OK')\"\n"
            "    Verify qdrant_client is available in venv",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don\u2019t ask again for: .venv/Scripts/python.exe:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_bash_3opt_dont_ask_again_wmic(self):
        """From screenshot: wmic process with 'don't ask again for: wmic process:*'."""
        screen = self._make_screen(
            "Bash command\n"
            "\n"
            "    wmic process where \"ProcessId=27340 or ProcessId=19152\" "
            "get ProcessId,CommandLine /format:list 2>/dev/null | head -20\n"
            "    Identify which python process is the embedder",
            "Do you want to proceed?\n"
            "❯ 1. Yes\n"
            "  2. Yes, and don\u2019t ask again for: wmic process:*\n"
            "  3. No\n"
            "\n"
            "Esc to cancel · Tab to amend · ctrl+e to explain",
        )
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    # ── Other prompt types ─────────────────────────────────────────────

    def test_trust_folder(self):
        screen = self._make_screen(
            "Starting Claude Code...",
            "Do you trust this directory?\n  /home/user/project",
        )
        assert agentnanny.detect_prompt(screen) == ("trust", 0)

    def test_codex_startup_prompt_detected(self):
        screen = self._make_screen(
            "Codex starting",
            "Do you trust this directory?",
        )
        assert agentnanny.detect_codex_startup_prompt(screen)

    def test_continue_prompt(self):
        screen = self._make_screen(
            "Long output...",
            "Continue? Press Enter to continue",
        )
        assert agentnanny.detect_prompt(screen) == ("continue", 0)

    # ── Negative cases ─────────────────────────────────────────────────

    def test_no_prompt_normal_output(self):
        screen = self._make_screen(
            "Code output",
            "function hello() {\n  console.log('hi')\n}",
        )
        assert agentnanny.detect_prompt(screen) is None

    def test_no_prompt_empty_below(self):
        screen = self._make_screen("Code output", "")
        assert agentnanny.detect_prompt(screen) is None

    def test_slash_picker_vetoed(self):
        screen = self._make_screen(
            "Command palette",
            "/commit  Create a git commit\n/help  Show help\n/clear  Clear screen",
        )
        assert agentnanny.detect_prompt(screen) is None

    def test_no_separator_fallback(self):
        lines = ["normal output"] * 20 + [
            "Do you want to proceed?",
            "❯ 1. Yes",
            "  2. Yes, allow for this project",
            "  3. No",
        ]
        screen = "\n".join(lines)
        assert agentnanny.detect_prompt(screen) == ("permission", 3)

    def test_no_separator_no_prompt(self):
        lines = ["normal output"] * 20
        screen = "\n".join(lines)
        assert agentnanny.detect_prompt(screen) is None

    def test_plain_text_with_yes_no_not_prompt(self):
        """Numbered list in normal output that isn't a permission prompt."""
        screen = self._make_screen(
            "Instructions",
            "Steps:\n1. Yes, install the package\n2. No need for config",
        )
        assert agentnanny.detect_prompt(screen) is None

    def test_allow_cookies_not_prompt(self):
        screen = self._make_screen(
            "Config",
            "allow_cookies = true\nsome other config",
        )
        assert agentnanny.detect_prompt(screen) is None


# ═══════════════════════════════════════════════════════════════════════════
# Collapsed transcript detection
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectCollapsed:
    def test_ctrl_o_indicator(self):
        assert agentnanny.detect_collapsed("Press Ctrl+O to expand transcript") is True

    def test_collapsed_text(self):
        assert agentnanny.detect_collapsed("▶ collapsed transcript (15 items)") is True

    def test_no_collapsed(self):
        assert agentnanny.detect_collapsed("normal code output here") is False

    def test_empty(self):
        assert agentnanny.detect_collapsed("") is False


# ═══════════════════════════════════════════════════════════════════════════
# Install / Uninstall
# ═══════════════════════════════════════════════════════════════════════════


class TestInstallUninstall:
    def test_install_creates_hook(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        perm = settings["hooks"]["PermissionRequest"]
        assert len(perm) == 1
        assert "agentnanny" in perm[0]["hooks"][0]["command"]

    def test_install_preserves_existing_settings(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text(json.dumps({
            "permissions": {"allow": ["Bash"]},
            "other_setting": True,
        }), encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        assert settings["permissions"]["allow"] == ["Bash"]
        assert settings["other_setting"] is True
        assert "hooks" in settings

    def test_install_idempotent(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()
            with pytest.raises(SystemExit):
                agentnanny.install_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        perm = settings["hooks"]["PermissionRequest"]
        assert len(perm) == 1  # Not duplicated

    def test_install_creates_settings_file(self, tmp_path):
        settings_file = tmp_path / ".claude" / "settings.json"

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()

        assert settings_file.exists()
        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        assert "hooks" in settings

    def test_uninstall_removes_hook(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()
            agentnanny.uninstall_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        # hooks key should be cleaned up
        assert "hooks" not in settings or not settings.get("hooks")

    def test_uninstall_preserves_other_hooks(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text(json.dumps({
            "hooks": {
                "PermissionRequest": [
                    {
                        "matcher": "",
                        "hooks": [{"type": "command", "command": "other-tool hook"}],
                    },
                ],
            },
        }), encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()
            agentnanny.uninstall_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        perm = settings["hooks"]["PermissionRequest"]
        assert len(perm) == 1
        assert "other-tool" in perm[0]["hooks"][0]["command"]

    def test_uninstall_no_hooks_exits(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            with pytest.raises(SystemExit):
                agentnanny.uninstall_hooks()

    def test_uninstall_no_settings_file(self, tmp_path):
        settings_file = tmp_path / "settings.json"

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            with pytest.raises(SystemExit):
                agentnanny.uninstall_hooks()


# ═══════════════════════════════════════════════════════════════════════════
# Trust directory
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustDirectory:
    def test_trust_new_directory(self, tmp_path):
        claude_json = tmp_path / ".claude.json"

        with patch.object(agentnanny, "CLAUDE_JSON_PATH", claude_json):
            agentnanny.trust_directory(str(tmp_path / "myproject"))

        settings = json.loads(claude_json.read_text(encoding="utf-8"))
        proj_key = str((tmp_path / "myproject").resolve())
        assert settings["projects"][proj_key]["hasTrustDialogAccepted"] is True

    def test_trust_codex_new_directory(self, tmp_path):
        trust_file = tmp_path / "trust.json"

        with patch.object(agentnanny, "CODEX_TRUST_PATH", trust_file):
            agentnanny.trust_directory(str(tmp_path / "myproject"), target="codex")

        settings = json.loads(trust_file.read_text(encoding="utf-8"))
        expected = str((tmp_path / "myproject").resolve())
        assert settings == {"trusted_directories": [expected]}

    def test_trust_preserves_existing(self, tmp_path):
        claude_json = tmp_path / ".claude.json"
        claude_json.write_text(json.dumps({
            "numStartups": 5,
            "projects": {
                "/existing": {"hasTrustDialogAccepted": True},
            },
        }), encoding="utf-8")

        with patch.object(agentnanny, "CLAUDE_JSON_PATH", claude_json):
            agentnanny.trust_directory(str(tmp_path / "newproject"))

        settings = json.loads(claude_json.read_text(encoding="utf-8"))
        assert settings["numStartups"] == 5
        assert settings["projects"]["/existing"]["hasTrustDialogAccepted"] is True

    def test_trust_codex_preserves_existing(self, tmp_path):
        trust_file = tmp_path / "trust.json"
        trust_file.write_text(json.dumps({
            "trusted_directories": ["/existing"],
        }), encoding="utf-8")

        with patch.object(agentnanny, "CODEX_TRUST_PATH", trust_file):
            agentnanny.trust_directory(str(tmp_path / "newproject"), target="codex")

        settings = json.loads(trust_file.read_text(encoding="utf-8"))
        assert settings["trusted_directories"] == ["/existing", str((tmp_path / "newproject").resolve())]

    def test_trust_creates_file(self, tmp_path):
        claude_json = tmp_path / ".claude.json"

        with patch.object(agentnanny, "CLAUDE_JSON_PATH", claude_json):
            agentnanny.trust_directory(str(tmp_path))

        assert claude_json.exists()

    def test_trust_invalid_target(self, tmp_path):
        with patch.object(agentnanny, "CODEX_TRUST_PATH", tmp_path / "trust.json"):
            with pytest.raises(ValueError, match="Unsupported trust target"):
                agentnanny.trust_directory(str(tmp_path), target="unknown")


# ═══════════════════════════════════════════════════════════════════════════
# Audit log
# ═══════════════════════════════════════════════════════════════════════════


class TestAuditLog:
    def test_log_write(self, tmp_path):
        log_file = tmp_path / "test.log"
        cfg = {"logging": {"audit_log": str(log_file), "level": "all"}}

        agentnanny.audit_log("hook", "allowed", "Bash", "command=ls", cfg)

        content = log_file.read_text(encoding="utf-8")
        assert "hook" in content
        assert "allowed" in content
        assert "Bash" in content
        assert "command=ls" in content

    def test_log_level_actions(self, tmp_path):
        log_file = tmp_path / "test.log"
        cfg = {"logging": {"audit_log": str(log_file), "level": "actions"}}

        agentnanny.audit_log("hook", "allowed", "Bash", "ls", cfg)
        agentnanny.audit_log("hook", "checked", "Bash", "ls", cfg)  # Not an action

        content = log_file.read_text(encoding="utf-8")
        assert "allowed" in content
        assert "checked" not in content

    def test_log_tsv_format(self, tmp_path):
        log_file = tmp_path / "test.log"
        cfg = {"logging": {"audit_log": str(log_file), "level": "all"}}

        agentnanny.audit_log("hook", "allowed", "Bash", "ls", cfg)

        line = log_file.read_text(encoding="utf-8").strip()
        parts = line.split("\t")
        assert len(parts) == 5  # timestamp, source, action, tool, detail


# ═══════════════════════════════════════════════════════════════════════════
# Config loading
# ═══════════════════════════════════════════════════════════════════════════


class TestLoadConfig:
    def test_load_from_file(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('[hooks]\ndeny = ["Bash(rm*)"]\n[daemon]\nsession = "test"', encoding="utf-8")

        with patch.object(agentnanny, "CONFIG_PATH", config_file):
            cfg = agentnanny.load_config()

        assert cfg["hooks"]["deny"] == ["Bash(rm*)"]
        assert cfg["daemon"]["session"] == "test"

    def test_env_override_session(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text('[daemon]\nsession = "default"', encoding="utf-8")

        with patch.object(agentnanny, "CONFIG_PATH", config_file), \
             patch.dict(os.environ, {"AGENTNANNY_SESSION": "override"}):
            cfg = agentnanny.load_config()

        assert cfg["daemon"]["session"] == "override"

    def test_env_override_deny(self, tmp_path):
        config_file = tmp_path / "config.toml"
        config_file.write_text("[hooks]\ndeny = []", encoding="utf-8")

        with patch.object(agentnanny, "CONFIG_PATH", config_file), \
             patch.dict(os.environ, {"AGENTNANNY_DENY": "Bash(rm*),WebFetch"}):
            cfg = agentnanny.load_config()

        assert cfg["hooks"]["deny"] == ["Bash(rm*)", "WebFetch"]

    def test_missing_config_file(self, tmp_path):
        config_file = tmp_path / "nonexistent.toml"

        with patch.object(agentnanny, "CONFIG_PATH", config_file):
            cfg = agentnanny.load_config()

        assert isinstance(cfg, dict)
        assert "hooks" in cfg


# ═══════════════════════════════════════════════════════════════════════════
# CLI argument parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestCLI:
    def test_no_command_exits(self):
        with patch("sys.argv", ["agentnanny"]):
            with pytest.raises(SystemExit):
                agentnanny.main()

    def test_hook_command(self):
        """Hook via CLI with no scope → passthrough (empty output)."""
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        stdin = StringIO(json.dumps(event))
        stdout = StringIO()
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}

        with patch("sys.argv", ["agentnanny", "hook"]), \
             patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.main()

        assert stdout.getvalue() == ""

    def test_status_command(self, tmp_path, capsys):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")
        pid_file = tmp_path / "agentnanny.pid"

        with patch("sys.argv", ["agentnanny", "status"]), \
             patch.object(agentnanny, "SETTINGS_PATH", settings_file), \
             patch.object(agentnanny, "PID_FILE", pid_file), \
             patch.object(agentnanny, "SESSION_DIR", tmp_path / "sessions"), \
             patch.object(agentnanny, "load_config", return_value={"hooks": {}}), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            agentnanny.main()

        output = capsys.readouterr().out
        assert "Hook installed: no" in output
        assert "Daemon running: no" in output


# ═══════════════════════════════════════════════════════════════════════════
# Session policies
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionPolicy:
    def test_save_and_load_roundtrip(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            policy = {
                "scope_id": "abc12345",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": ["filesystem"],
                "allow_tools": ["Bash"],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            loaded = agentnanny.load_session_policy("abc12345")
            assert loaded is not None
            assert loaded["scope_id"] == "abc12345"
            assert loaded["allow_groups"] == ["filesystem"]

    def test_load_nonexistent(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            assert agentnanny.load_session_policy("deadbeef") is None

    def test_expired_policy_returns_none(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            created = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(timespec="seconds")
            policy = {
                "scope_id": "e00e0001",
                "created": created,
                "ttl_seconds": 1,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            assert agentnanny.load_session_policy("e00e0001") is None
            # File should be deleted
            assert not (tmp_path / "expired1.json").exists()

    def test_no_ttl_never_expires(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            created = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(timespec="seconds")
            policy = {
                "scope_id": "f00e0e01",
                "created": created,
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            assert agentnanny.load_session_policy("f00e0e01") is not None

    def test_delete_policy(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            policy = {
                "scope_id": "de012345",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            assert agentnanny.delete_session_policy("de012345") is True
            assert agentnanny.delete_session_policy("de012345") is False

    def test_list_policies(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            for i in range(3):
                agentnanny.save_session_policy({
                    "scope_id": f"a0a0{i:04d}",
                    "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "ttl_seconds": 0,
                    "allow_groups": [],
                    "allow_tools": [],
                    "deny": [],
                })
            policies = agentnanny.list_session_policies()
            assert len(policies) == 3

    def test_generate_scope_id(self):
        sid = agentnanny.generate_scope_id()
        assert len(sid) == 8
        int(sid, 16)  # Must be valid hex


# ═══════════════════════════════════════════════════════════════════════════
# Scope ID validation
# ═══════════════════════════════════════════════════════════════════════════


class TestScopeIdValidation:
    def test_valid_hex_ids(self):
        for sid in ("abcdef01", "00000000", "deadbeef", "face1234", "be001234"):
            assert agentnanny._valid_scope_id(sid) is True

    def test_invalid_ids(self):
        for sid in ("../etc/passwd", "ABCD1234", "short", "toolong12", "", "zzzzzzzz"):
            assert agentnanny._valid_scope_id(sid) is False

    def test_load_rejects_invalid_scope(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            # Write a file that would match a traversal path
            (tmp_path / "../evil.json").resolve().parent.mkdir(parents=True, exist_ok=True)
            assert agentnanny.load_session_policy("../evil") is None

    def test_delete_rejects_invalid_scope(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            assert agentnanny.delete_session_policy("../evil") is False

    def test_deactivate_rejects_invalid_scope(self):
        with pytest.raises(SystemExit):
            agentnanny.cmd_deactivate("../evil")


# ═══════════════════════════════════════════════════════════════════════════
# File permissions
# ═══════════════════════════════════════════════════════════════════════════


@pytest.mark.skipif(sys.platform == "win32", reason="Unix file permissions not supported on Windows")
class TestFilePermissions:
    def test_session_file_is_owner_only(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            policy = {
                "scope_id": "face1234",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            path = agentnanny.save_session_policy(policy)
            mode = path.stat().st_mode & 0o777
            assert mode == 0o600

    def test_tmp_file_never_world_readable(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            policy = {
                "scope_id": "cafe0001",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            tmp_files = list(tmp_path.glob("*.tmp"))
            assert tmp_files == []

    def test_session_dir_is_owner_only(self, tmp_path):
        session_dir = tmp_path / "sessions"
        with patch.object(agentnanny, "SESSION_DIR", session_dir):
            policy = {
                "scope_id": "cafe0002",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            }
            agentnanny.save_session_policy(policy)
            mode = session_dir.stat().st_mode & 0o777
            assert mode == 0o700


# ═══════════════════════════════════════════════════════════════════════════
# Group resolution
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveGroups:
    CFG = {
        "groups": {
            "filesystem": ["Read", "Write", "Edit", "Glob", "Grep"],
            "shell": ["Bash"],
            "network": ["WebFetch", "WebSearch"],
            "all": [".*"],
        }
    }

    def test_single_group(self):
        result = agentnanny.resolve_groups(["shell"], self.CFG)
        assert result == ["Bash"]

    def test_multiple_groups(self):
        result = agentnanny.resolve_groups(["filesystem", "shell"], self.CFG)
        assert "Read" in result
        assert "Write" in result
        assert "Bash" in result

    def test_unknown_group_raises(self):
        with pytest.raises(ValueError, match="Unknown group"):
            agentnanny.resolve_groups(["nonexistent"], self.CFG)

    def test_empty_groups(self):
        result = agentnanny.resolve_groups([], self.CFG)
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════
# Allow matching
# ═══════════════════════════════════════════════════════════════════════════


class TestMatchesAllow:
    def test_exact_tool_name(self):
        assert agentnanny.matches_allow("Bash", {}, ["Bash"]) is True

    def test_exact_tool_name_no_match(self):
        assert agentnanny.matches_allow("WebFetch", {}, ["Bash"]) is False

    def test_tool_with_input_pattern(self):
        assert agentnanny.matches_allow(
            "Bash", {"command": "ls -la"}, ["Bash(ls*)"]
        ) is True

    def test_tool_with_input_pattern_no_match(self):
        assert agentnanny.matches_allow(
            "Bash", {"command": "rm -rf /"}, ["Bash(ls*)"]
        ) is False

    def test_regex_pattern(self):
        assert agentnanny.matches_allow("WebFetch", {}, [".*Fetch.*"]) is True

    def test_wildcard_all(self):
        assert agentnanny.matches_allow("AnyTool", {}, [".*"]) is True

    def test_no_match(self):
        assert agentnanny.matches_allow("Bash", {}, ["Read", "Write"]) is False


# ═══════════════════════════════════════════════════════════════════════════
# Hook handler — session-scoped mode
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleHookScoped:
    GROUPS_CFG = {
        "groups": {
            "filesystem": ["Read", "Write", "Edit", "Glob", "Grep"],
            "shell": ["Bash"],
        }
    }

    def _run_hook_scoped(self, event: dict, scope_id: str | None = None,
                         policy: dict | None = None, cfg_extra: dict | None = None,
                         global_deny: list[str] | None = None) -> str:
        """Run handle_hook with optional session scope. Returns raw stdout."""
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}
        cfg.update(self.GROUPS_CFG)
        if global_deny:
            cfg["hooks"]["deny"] = global_deny
        if cfg_extra:
            cfg.update(cfg_extra)

        stdin = StringIO(json.dumps(event))
        stdout = StringIO()

        env_patch = {}
        if scope_id:
            env_patch["AGENTNANNY_SCOPE"] = scope_id

        with patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.dict(os.environ, env_patch, clear=False):
            if not scope_id:
                os.environ.pop("AGENTNANNY_SCOPE", None)
            if policy:
                with patch.object(agentnanny, "load_session_policy", return_value=policy):
                    agentnanny.handle_hook()
            else:
                agentnanny.handle_hook()

        return stdout.getvalue()

    def test_no_scope_passthrough(self):
        """Without AGENTNANNY_SCOPE and no allow list, hook passes through."""
        raw = self._run_hook_scoped({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        })
        assert raw == ""

    def test_scope_valid_policy_allows(self):
        """Tool in session allow groups gets allowed."""
        policy = {
            "scope_id": "be001234",
            "allow_groups": ["filesystem"],
            "allow_tools": [],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}},
            scope_id="be001234",
            policy=policy,
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_scope_tool_not_in_allow_passthrough(self):
        """Tool not in session allow list → passthrough (empty output)."""
        policy = {
            "scope_id": "be001234",
            "allow_groups": ["filesystem"],
            "allow_tools": [],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            scope_id="be001234",
            policy=policy,
        )
        assert raw == ""

    def test_scope_explicit_tool_allows(self):
        """Explicit tool name in allow_tools gets allowed."""
        policy = {
            "scope_id": "be001234",
            "allow_groups": [],
            "allow_tools": ["WebFetch"],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "WebFetch", "tool_input": {"url": "http://x"}},
            scope_id="be001234",
            policy=policy,
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "allow"

    def test_scope_global_deny_still_applies(self):
        """Global deny list blocks even with valid session scope."""
        policy = {
            "scope_id": "be001234",
            "allow_groups": ["shell"],
            "allow_tools": [],
            "deny": [],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            scope_id="be001234",
            policy=policy,
            global_deny=["Bash(rm*)"],
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_scope_session_deny_applies(self):
        """Session-level deny blocks the tool."""
        policy = {
            "scope_id": "be001234",
            "allow_groups": ["shell"],
            "allow_tools": [],
            "deny": ["Bash(rm*)"],
        }
        raw = self._run_hook_scoped(
            {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
            scope_id="be001234",
            policy=policy,
        )
        result = json.loads(raw)
        assert result["hookSpecificOutput"]["decision"]["behavior"] == "deny"

    def test_scope_missing_policy_passthrough(self):
        """Missing policy file → passthrough."""
        raw = self._run_hook_scoped(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}},
            scope_id="deadbeef",
            policy=None,
        )
        assert raw == ""

    def test_scope_expired_policy_passthrough(self, tmp_path):
        """Expired policy → passthrough."""
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            created = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat(timespec="seconds")
            agentnanny.save_session_policy({
                "scope_id": "e00e0001",
                "created": created,
                "ttl_seconds": 1,
                "allow_groups": ["shell"],
                "allow_tools": [],
                "deny": [],
            })
            raw = self._run_hook_scoped(
                {"tool_name": "Bash", "tool_input": {"command": "ls"}},
                scope_id="e00e0001",
            )
            assert raw == ""


# ═══════════════════════════════════════════════════════════════════════════
# Activate / Deactivate commands
# ═══════════════════════════════════════════════════════════════════════════


class TestActivateDeactivate:
    def test_activate_creates_policy(self, tmp_path, capsys):
        cfg = {
            "hooks": {},
            "groups": {"filesystem": ["Read", "Write", "Edit", "Glob", "Grep"]},
            "logging": {"audit_log": os.devnull},
        }
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_activate(None, "filesystem", None, None, "0")

        out = capsys.readouterr().out
        assert out.startswith("export AGENTNANNY_SCOPE=")
        scope_id = out.strip().split("=")[1]
        assert (tmp_path / f"{scope_id}.json").exists()

    def test_activate_with_ttl(self, tmp_path, capsys):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_activate(None, None, "Bash", None, "8h")

        out = capsys.readouterr().out
        scope_id = out.strip().split("=")[1]
        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert policy["ttl_seconds"] == 28800

    def test_activate_unknown_group_raises(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            with pytest.raises(ValueError, match="Unknown group"):
                agentnanny.cmd_activate(None, "nonexistent", None, None, "0")

    def test_deactivate_removes_policy(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.save_session_policy({
                "scope_id": "dea01234",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            })
            agentnanny.cmd_deactivate("dea01234")

        assert not (tmp_path / "deact123.json").exists()
        out = capsys.readouterr().out
        assert "unset AGENTNANNY_SCOPE" in out

    def test_deactivate_from_env(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.dict(os.environ, {"AGENTNANNY_SCOPE": "f00e0001"}):
            agentnanny.save_session_policy({
                "scope_id": "f00e0001",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            })
            agentnanny.cmd_deactivate(None)

        assert not (tmp_path / "fromenv1.json").exists()

    def test_deactivate_nonexistent_exits(self, tmp_path):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            with pytest.raises(SystemExit):
                agentnanny.cmd_deactivate("decade01")

    def test_deactivate_no_scope_exits(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            with pytest.raises(SystemExit):
                agentnanny.cmd_deactivate(None)


# ═══════════════════════════════════════════════════════════════════════════
# Extend
# ═══════════════════════════════════════════════════════════════════════════


class TestExtend:
    def _create_session(self, tmp_path, scope_id, groups=None, tools=None, deny=None):
        """Helper to create a session policy for testing."""
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ttl_seconds": 0,
            "allow_groups": groups or [],
            "allow_tools": tools or [],
            "deny": deny or [],
        }
        agentnanny.save_session_policy(policy)
        return policy

    def test_extend_adds_groups(self, tmp_path):
        cfg = {
            "hooks": {},
            "groups": {
                "filesystem": ["Read", "Write", "Edit", "Glob", "Grep"],
                "network": ["WebFetch", "WebSearch"],
            },
            "logging": {"audit_log": os.devnull},
        }
        scope_id = "a1b2c3d4"
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            self._create_session(tmp_path, scope_id, groups=["filesystem"])
            agentnanny.cmd_extend(scope_id, "network", None, None)

        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert "filesystem" in policy["allow_groups"]
        assert "network" in policy["allow_groups"]

    def test_extend_adds_tools(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        scope_id = "b2c3d4e5"
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            self._create_session(tmp_path, scope_id, tools=["Read"])
            agentnanny.cmd_extend(scope_id, None, "Write,Edit", None)

        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert policy["allow_tools"] == ["Read", "Write", "Edit"]

    def test_extend_adds_deny(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        scope_id = "c3d4e5f6"
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            self._create_session(tmp_path, scope_id, deny=["Bash(rm*)"])
            agentnanny.cmd_extend(scope_id, None, None, "Bash(sudo*)")

        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert "Bash(rm*)" in policy["deny"]
        assert "Bash(sudo*)" in policy["deny"]

    def test_extend_deduplicates(self, tmp_path):
        cfg = {
            "hooks": {},
            "groups": {"filesystem": ["Read", "Write", "Edit", "Glob", "Grep"]},
            "logging": {"audit_log": os.devnull},
        }
        scope_id = "d4e5f6a7"
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            self._create_session(tmp_path, scope_id, groups=["filesystem"], tools=["Bash"])
            agentnanny.cmd_extend(scope_id, "filesystem", "Bash", None)

        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert policy["allow_groups"].count("filesystem") == 1
        assert policy["allow_tools"].count("Bash") == 1

    def test_extend_nonexistent_session(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            with pytest.raises(SystemExit):
                agentnanny.cmd_extend("deadbeef", "filesystem", None, None)

    def test_extend_uses_env_scope(self, tmp_path):
        cfg = {
            "hooks": {},
            "groups": {"network": ["WebFetch", "WebSearch"]},
            "logging": {"audit_log": os.devnull},
        }
        scope_id = "e5f6a7b8"
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.dict(os.environ, {"AGENTNANNY_SCOPE": scope_id}):
            self._create_session(tmp_path, scope_id)
            agentnanny.cmd_extend(None, "network", None, None)

        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert "network" in policy["allow_groups"]

    def test_extend_no_scope(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            with pytest.raises(SystemExit):
                agentnanny.cmd_extend(None, None, None, None)

    def test_extend_validates_groups(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        scope_id = "f6a7b8c9"
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            self._create_session(tmp_path, scope_id)
            with pytest.raises(ValueError, match="Unknown group"):
                agentnanny.cmd_extend(scope_id, "nonexistent_group", None, None)


# ═══════════════════════════════════════════════════════════════════════════
# Run wrapper
# ═══════════════════════════════════════════════════════════════════════════


class TestRunWrapper:
    class _FakeCodexStdout:
        def __init__(self, chunks: list[str]):
            self.chunks = chunks

        def readline(self):
            return self.chunks.pop(0) if self.chunks else ""

        def close(self):
            self.chunks = []

    class _FakeCodexStdin:
        def __init__(self):
            self.sent: list[str] = []

        def write(self, value: str):
            self.sent.append(value)

        def flush(self):
            return None

        def close(self):
            return None

    class _FakeCodexProcess:
        def __init__(self, chunks: list[str], return_code: int = 0):
            self.stdout = TestRunWrapper._FakeCodexStdout(chunks)
            self.stdin = TestRunWrapper._FakeCodexStdin()
            self._return_code = return_code
            self.poll_count = 0

        def poll(self) -> int | None:
            # Simulate process completion only after all output is consumed.
            if self.stdout.chunks:
                return None
            self.poll_count += 1
            return self._return_code

        def wait(self):
            return self._return_code

    def test_run_compiles_completion_patterns(self):
        patterns = agentnanny._compile_completion_patterns("done,success\\s+message")
        assert len(patterns) == 2
        assert patterns[0].pattern == "done"
        assert patterns[1].pattern == "success\\s+message"

    def test_run_codex_process_detects_startup_and_completion(self, tmp_path, monkeypatch):
        fake_proc = self._FakeCodexProcess([
            "Starting...\n",
            "Do you trust this directory?\n",
            "Task complete\n",
        ], return_code=0)

        def fake_popen(*_args, **_kwargs):
            return fake_proc

        monkeypatch.setattr(agentnanny.subprocess, "Popen", fake_popen)
        monkeypatch.setattr(agentnanny, "_is_codex_trusted", lambda directory: False)
        added: list[str] = []
        monkeypatch.setattr(agentnanny, "_add_codex_trusted_directory", lambda directory: added.append(directory))

        result = agentnanny.run_codex_session(["codex"], os.environ.copy(), completion="Task complete", working_directory=str(tmp_path))

        assert result["return_code"] == 0
        assert result["startup_prompt_seen"] is True
        assert result["completion"]["matched"] is True
        assert result["completion"]["criteria_count"] == 1
        assert result["completion"]["criteria"] == ["Task complete"]
        assert result["output_length"] > 0
        assert fake_proc.stdin.sent == ["y\n"]
        assert added == [str(tmp_path)]

    def test_run_codex_process_completes_without_startup(self, tmp_path, monkeypatch):
        fake_proc = self._FakeCodexProcess([
            "Booting tools...\n",
            "still working...\n",
            "Task complete\n",
        ], return_code=0)

        def fake_popen(*_args, **_kwargs):
            return fake_proc

        monkeypatch.setattr(agentnanny.subprocess, "Popen", fake_popen)
        monkeypatch.setattr(agentnanny, "_is_codex_trusted", lambda directory: True)

        result = agentnanny.run_codex_session(
            ["codex"],
            os.environ.copy(),
            completion="Task complete,All done",
            working_directory=str(tmp_path),
        )

        assert result["return_code"] == 0
        assert result["startup_prompt_seen"] is False
        assert result["completion"]["matched"] is True
        assert result["completion"]["pattern"] == "Task complete"
        assert result["completion"]["criteria_count"] == 2
        assert result["completion"]["criteria"] == ["Task complete", "All done"]

    def test_run_codex_process_with_no_completion_patterns(self, monkeypatch):
        fake_proc = self._FakeCodexProcess(["done\n"], return_code=0)

        def fake_popen(*_args, **_kwargs):
            return fake_proc

        monkeypatch.setattr(agentnanny.subprocess, "Popen", fake_popen)

        result = agentnanny.run_codex_session(["codex"], os.environ.copy(), completion=None)

        assert result["completion"]["matched"] is False
        assert result["completion"]["criteria_count"] == 0
        assert result["completion"]["criteria"] == []
        assert result["completion"]["pattern"] is None

    def test_run_codex_uses_codex_runner(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        fake_result = {
            "return_code": 7,
            "startup_prompt_seen": True,
            "completion": {"matched": True, "pattern": "done", "criteria_count": 1, "criteria": ["done"]},
            "started_at": "2026-01-01T00:00:00+00:00",
            "ended_at": "2026-01-01T00:00:01+00:00",
            "output_length": 42,
        }
        captured = {}

        def fake_run_codex_session(args, env, completion=None, working_directory=None):
            captured["args"] = args
            captured["env"] = env.copy()
            captured["completion"] = completion
            captured["working_directory"] = working_directory
            return fake_result

        def fake_apply(_policy, _cfg, scope_id):
            captured["applied"] = scope_id

        def fake_remove(scope_id):
            captured["removed"] = scope_id

        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.object(agentnanny, "_apply_codex_session", fake_apply), \
             patch.object(agentnanny, "_remove_codex_session", fake_remove), \
             patch.object(agentnanny, "run_codex_session", fake_run_codex_session), \
             pytest.raises(SystemExit) as exc_info:
            agentnanny.cmd_run(None, None, None, None, None, ["--", "codex", "run"], "done", "codex")

        assert exc_info.value.code == 7
        scope_id = captured["env"]["AGENTNANNY_SCOPE"]
        assert captured["args"] == ["codex", "run"]
        assert captured["completion"] == "done"
        assert captured["working_directory"] == str(Path.cwd())
        assert captured["applied"] == scope_id
        assert captured["removed"] == scope_id

    def test_run_sets_env_and_cleans_up(self, tmp_path):
        cfg = {"hooks": {}, "groups": {}, "logging": {"audit_log": os.devnull}}
        captured_env = {}

        def mock_run(args, env=None):
            captured_env.update(env or {})
            return subprocess.CompletedProcess(args, 0)

        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch("subprocess.run", mock_run), \
             pytest.raises(SystemExit) as exc_info:
            agentnanny.cmd_run(None, None, "Bash", None, "0", ["--", "echo", "hello"])

        assert exc_info.value.code == 0
        assert "AGENTNANNY_SCOPE" in captured_env
        scope_id = captured_env["AGENTNANNY_SCOPE"]
        # Policy should be cleaned up
        assert not (tmp_path / f"{scope_id}.json").exists()

    def test_run_no_command_exits(self):
        with pytest.raises(SystemExit):
            agentnanny.cmd_run(None, None, None, None, "0", [])

    def test_run_no_command_after_separator_exits(self):
        with pytest.raises(SystemExit):
            agentnanny.cmd_run(None, None, None, None, "0", ["--"])


# ═══════════════════════════════════════════════════════════════════════════
# Sessions listing
# ═══════════════════════════════════════════════════════════════════════════


class TestSessions:
    def test_list_empty(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.cmd_sessions()
        assert "No active sessions" in capsys.readouterr().out

    def test_list_shows_policies(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.save_session_policy({
                "scope_id": "5e551234",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": ["shell"],
                "allow_tools": [],
                "deny": [],
            })
            agentnanny.cmd_sessions()
        out = capsys.readouterr().out
        assert "5e551234" in out
        assert "shell" in out


# ═══════════════════════════════════════════════════════════════════════════
# TTL parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestParseTtl:
    def test_hours(self):
        assert agentnanny._parse_ttl("8h") == 28800

    def test_minutes(self):
        assert agentnanny._parse_ttl("30m") == 1800

    def test_seconds_suffix(self):
        assert agentnanny._parse_ttl("60s") == 60

    def test_bare_number(self):
        assert agentnanny._parse_ttl("3600") == 3600

    def test_zero(self):
        assert agentnanny._parse_ttl("0") == 0


# ═══════════════════════════════════════════════════════════════════════════
# TOML parser: hyphenated keys
# ═══════════════════════════════════════════════════════════════════════════


class TestTomlHyphens:
    def test_hyphenated_table_name(self):
        text = '[profiles.safe-dev]\ngroups = ["filesystem", "safe-shell"]'
        result = agentnanny.parse_toml(text)
        assert result["profiles"]["safe-dev"]["groups"] == ["filesystem", "safe-shell"]

    def test_hyphenated_key_name(self):
        text = '[groups]\nsafe-shell = ["Bash(ls*)"]'
        result = agentnanny.parse_toml(text)
        assert result["groups"]["safe-shell"] == ["Bash(ls*)"]

    def test_nested_hyphenated_tables(self):
        text = '[profiles.ci-runner]\nttl = "1h"\ngroups = ["shell"]'
        result = agentnanny.parse_toml(text)
        assert result["profiles"]["ci-runner"]["ttl"] == "1h"
        assert result["profiles"]["ci-runner"]["groups"] == ["shell"]


# ═══════════════════════════════════════════════════════════════════════════
# Built-in constants
# ═══════════════════════════════════════════════════════════════════════════


class TestBuiltinConstants:
    def test_all_expected_groups_defined(self):
        expected = {"read-only", "write", "filesystem", "shell", "safe-shell",
                    "review-shell", "network", "all"}
        assert set(agentnanny.BUILTIN_GROUPS.keys()) == expected

    def test_all_expected_profiles_defined(self):
        expected = {"safe-dev", "full-dev", "reviewer", "overnight", "ci-runner"}
        assert set(agentnanny.BUILTIN_PROFILES.keys()) == expected

    def test_profiles_have_required_keys(self):
        for name, p in agentnanny.BUILTIN_PROFILES.items():
            assert "groups" in p, f"{name} missing groups"
            assert "deny" in p, f"{name} missing deny"
            assert "ttl" in p, f"{name} missing ttl"

    def test_profile_groups_reference_valid_groups(self):
        for name, p in agentnanny.BUILTIN_PROFILES.items():
            for g in p["groups"]:
                assert g in agentnanny.BUILTIN_GROUPS, (
                    f"Profile {name} references unknown group {g}"
                )


# ═══════════════════════════════════════════════════════════════════════════
# Deep merge
# ═══════════════════════════════════════════════════════════════════════════


class TestDeepMerge:
    def test_flat_merge(self):
        base = {"a": 1, "b": 2}
        overlay = {"b": 3, "c": 4}
        result = agentnanny._deep_merge(base, overlay)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"hooks": {"deny": ["A"], "allow": ["B"]}, "daemon": {"session": "x"}}
        overlay = {"hooks": {"deny": ["C"]}}
        result = agentnanny._deep_merge(base, overlay)
        assert result["hooks"]["deny"] == ["C"]
        assert result["hooks"]["allow"] == ["B"]
        assert result["daemon"]["session"] == "x"

    def test_non_dict_replaces(self):
        base = {"key": [1, 2, 3]}
        overlay = {"key": [4, 5]}
        result = agentnanny._deep_merge(base, overlay)
        assert result["key"] == [4, 5]

    def test_does_not_mutate_base(self):
        base = {"a": {"b": 1}}
        overlay = {"a": {"c": 2}}
        agentnanny._deep_merge(base, overlay)
        assert "c" not in base["a"]


# ═══════════════════════════════════════════════════════════════════════════
# Config paths
# ═══════════════════════════════════════════════════════════════════════════


class TestConfigPaths:
    def test_user_config_path_windows(self):
        with patch("sys.platform", "win32"), \
             patch.dict(os.environ, {"APPDATA": "C:\\Users\\X\\AppData\\Roaming"}):
            p = agentnanny._user_config_path()
            assert str(p).endswith("config.toml")
            assert "agentnanny" in str(p)

    def test_user_config_path_linux(self):
        with patch("sys.platform", "linux"), \
             patch.dict(os.environ, {"XDG_CONFIG_HOME": "/home/x/.config"}):
            p = agentnanny._user_config_path()
            # Path separators vary by OS; check components
            assert p.parts[-3:] == ("agentnanny", "config.toml")[-2:] or \
                   str(p).replace("\\", "/").endswith(".config/agentnanny/config.toml")

    def test_find_project_config_found(self, tmp_path):
        (tmp_path / ".agentnanny.toml").write_text("[hooks]\ndeny = []")
        sub = tmp_path / "sub" / "dir"
        sub.mkdir(parents=True)
        with patch("pathlib.Path.cwd", return_value=sub):
            result = agentnanny._find_project_config()
        assert result == tmp_path / ".agentnanny.toml"

    def test_find_project_config_not_found(self, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            result = agentnanny._find_project_config()
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# Layered config
# ═══════════════════════════════════════════════════════════════════════════


class TestLayeredConfig:
    def test_builtins_present_without_config(self, tmp_path):
        with patch.object(agentnanny, "CONFIG_PATH", tmp_path / "no.toml"), \
             patch.object(agentnanny, "_user_config_path", return_value=tmp_path / "no2.toml"), \
             patch.object(agentnanny, "_find_project_config", return_value=None):
            cfg = agentnanny.load_config()
        assert "safe-shell" in cfg["groups"]
        assert "safe-dev" in cfg["profiles"]
        assert "filesystem" in cfg["groups"]

    def test_script_adjacent_overrides_builtin(self, tmp_path):
        script_cfg = tmp_path / "config.toml"
        script_cfg.write_text('[groups]\nfilesystem = ["Read"]')
        with patch.object(agentnanny, "CONFIG_PATH", script_cfg), \
             patch.object(agentnanny, "_user_config_path", return_value=tmp_path / "no.toml"), \
             patch.object(agentnanny, "_find_project_config", return_value=None):
            cfg = agentnanny.load_config()
        assert cfg["groups"]["filesystem"] == ["Read"]
        # Other builtin groups still present
        assert "safe-shell" in cfg["groups"]

    def test_project_overrides_user(self, tmp_path):
        user_cfg = tmp_path / "user.toml"
        user_cfg.write_text('[hooks]\ndeny = ["Bash"]')
        proj_cfg = tmp_path / "proj.toml"
        proj_cfg.write_text('[hooks]\ndeny = ["WebFetch"]')
        with patch.object(agentnanny, "CONFIG_PATH", tmp_path / "no.toml"), \
             patch.object(agentnanny, "_user_config_path", return_value=user_cfg), \
             patch.object(agentnanny, "_find_project_config", return_value=proj_cfg):
            cfg = agentnanny.load_config()
        assert cfg["hooks"]["deny"] == ["WebFetch"]

    def test_custom_profile_in_config(self, tmp_path):
        script_cfg = tmp_path / "config.toml"
        script_cfg.write_text(
            '[profiles.my-custom]\ngroups = ["shell"]\ndeny = []\nttl = "2h"'
        )
        with patch.object(agentnanny, "CONFIG_PATH", script_cfg), \
             patch.object(agentnanny, "_user_config_path", return_value=tmp_path / "no.toml"), \
             patch.object(agentnanny, "_find_project_config", return_value=None):
            cfg = agentnanny.load_config()
        assert "my-custom" in cfg["profiles"]
        assert cfg["profiles"]["my-custom"]["groups"] == ["shell"]
        # Builtins still present
        assert "safe-dev" in cfg["profiles"]


# ═══════════════════════════════════════════════════════════════════════════
# Profile resolution
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveProfile:
    def _cfg(self):
        return {
            "groups": dict(agentnanny.BUILTIN_GROUPS),
            "profiles": {k: dict(v) for k, v in agentnanny.BUILTIN_PROFILES.items()},
        }

    def test_resolve_builtin(self):
        result = agentnanny.resolve_profile("safe-dev", self._cfg())
        assert result["groups"] == ["filesystem", "safe-shell"]
        assert result["ttl"] == "8h"
        assert result["deny"] == []

    def test_resolve_with_deny(self):
        result = agentnanny.resolve_profile("full-dev", self._cfg())
        assert len(result["deny"]) == 3
        assert any("rm -rf" in d for d in result["deny"])

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown profile.*Available"):
            agentnanny.resolve_profile("nonexistent", self._cfg())

    def test_custom_profile(self):
        cfg = self._cfg()
        cfg["profiles"]["custom"] = {"groups": ["shell"], "deny": [], "ttl": "1h"}
        result = agentnanny.resolve_profile("custom", cfg)
        assert result["groups"] == ["shell"]
        assert result["ttl"] == "1h"


# ═══════════════════════════════════════════════════════════════════════════
# Profile CLI integration
# ═══════════════════════════════════════════════════════════════════════════


class TestProfileCLI:
    def _cfg(self):
        return {
            "hooks": {},
            "groups": dict(agentnanny.BUILTIN_GROUPS),
            "profiles": {k: dict(v) for k, v in agentnanny.BUILTIN_PROFILES.items()},
            "logging": {"audit_log": os.devnull},
        }

    def test_activate_with_profile(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=self._cfg()):
            agentnanny.cmd_activate("safe-dev", None, None, None, None)

        out = capsys.readouterr().out
        scope_id = out.strip().split("=")[1]
        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert "filesystem" in policy["allow_groups"]
        assert "safe-shell" in policy["allow_groups"]
        assert policy["ttl_seconds"] == 28800  # 8h

    def test_activate_profile_plus_extra_deny(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=self._cfg()):
            agentnanny.cmd_activate("full-dev", None, None, "Bash(shutdown*)", None)

        out = capsys.readouterr().out
        scope_id = out.strip().split("=")[1]
        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert "Bash(shutdown*)" in policy["deny"]
        assert len(policy["deny"]) == 4  # 3 from full-dev + 1 extra

    def test_activate_profile_plus_extra_groups(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=self._cfg()):
            agentnanny.cmd_activate("reviewer", "network", None, None, None)

        out = capsys.readouterr().out
        scope_id = out.strip().split("=")[1]
        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert "read-only" in policy["allow_groups"]
        assert "review-shell" in policy["allow_groups"]
        assert "network" in policy["allow_groups"]

    def test_activate_profile_ttl_override(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=self._cfg()):
            agentnanny.cmd_activate("safe-dev", None, None, None, "2h")

        out = capsys.readouterr().out
        scope_id = out.strip().split("=")[1]
        policy = json.loads((tmp_path / f"{scope_id}.json").read_text())
        assert policy["ttl_seconds"] == 7200  # 2h overrides 8h

    def test_run_with_profile(self, tmp_path):
        captured_env = {}

        def mock_run(args, env=None):
            captured_env.update(env or {})
            return subprocess.CompletedProcess(args, 0)

        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.object(agentnanny, "load_config", return_value=self._cfg()), \
             patch("subprocess.run", mock_run), \
             pytest.raises(SystemExit) as exc_info:
            agentnanny.cmd_run("safe-dev", None, None, None, None, ["--", "echo", "hello"])

        assert exc_info.value.code == 0
        assert "AGENTNANNY_SCOPE" in captured_env
        scope_id = captured_env["AGENTNANNY_SCOPE"]
        assert not (tmp_path / f"{scope_id}.json").exists()  # cleaned up

    def test_list_profiles(self, capsys):
        with patch.object(agentnanny, "load_config", return_value=self._cfg()):
            agentnanny.cmd_list_profiles()
        out = capsys.readouterr().out
        assert "safe-dev" in out
        assert "full-dev" in out
        assert "reviewer" in out
        assert "overnight" in out
        assert "ci-runner" in out
        assert "builtin" in out

    def test_list_profiles_with_custom(self, capsys):
        cfg = self._cfg()
        cfg["profiles"]["my-custom"] = {"groups": ["shell"], "deny": [], "ttl": "2h"}
        with patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_list_profiles()
        out = capsys.readouterr().out
        assert "my-custom" in out
        assert "config" in out  # source label


# ═══════════════════════════════════════════════════════════════════════════
# Init command
# ═══════════════════════════════════════════════════════════════════════════


class TestInit:
    def test_creates_project_config(self, tmp_path, capsys):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            agentnanny.cmd_init()
        target = tmp_path / ".agentnanny.toml"
        assert target.exists()
        content = target.read_text()
        assert "[hooks]" in content
        assert "profiles" in content
        out = capsys.readouterr().out
        assert "Created" in out

    def test_refuses_if_exists(self, tmp_path):
        (tmp_path / ".agentnanny.toml").write_text("existing")
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with pytest.raises(SystemExit):
                agentnanny.cmd_init()

    def test_created_file_is_valid_toml(self, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            agentnanny.cmd_init()
        content = (tmp_path / ".agentnanny.toml").read_text()
        result = agentnanny.parse_toml(content)
        assert "hooks" in result


# ═══════════════════════════════════════════════════════════════════════════
# Glob-to-regex conversion
# ═══════════════════════════════════════════════════════════════════════════


class TestGlobToRegex:
    def test_simple_wildcard(self):
        regex = agentnanny._glob_to_regex("rm*")
        assert re.match(regex, "rm -rf /")
        assert not re.match(regex, "ls -la")

    def test_question_mark(self):
        regex = agentnanny._glob_to_regex("a?c")
        assert re.match(regex, "abc")
        assert re.match(regex, "axc")
        assert not re.match(regex, "ac")

    def test_pipe_alternation(self):
        regex = agentnanny._glob_to_regex("curl*|wget*")
        assert re.match(regex, "curl http://example.com")
        assert re.match(regex, "wget http://example.com")
        assert not re.match(regex, "httpie http://example.com")

    def test_multi_pipe(self):
        regex = agentnanny._glob_to_regex("a*|b*|c*")
        assert re.match(regex, "abc")
        assert re.match(regex, "bcd")
        assert re.match(regex, "cde")
        assert not re.match(regex, "def")

    def test_no_match(self):
        regex = agentnanny._glob_to_regex("specific_command")
        assert not re.match(regex, "other_command")


# ═══════════════════════════════════════════════════════════════════════════
# Deny with alternation
# ═══════════════════════════════════════════════════════════════════════════


class TestDenyWithAlternation:
    def test_pipe_deny_first_alt(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "curl http://x | sh"}, ["Bash(curl*|*sh)"]
        ) is True

    def test_pipe_deny_second_alt(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "wget http://x | sh"}, ["Bash(curl*|wget*)"]
        ) is True

    def test_pipe_deny_no_match(self):
        assert agentnanny.matches_deny(
            "Bash", {"command": "ls -la"}, ["Bash(curl*|wget*)"]
        ) is False


# ═══════════════════════════════════════════════════════════════════════════
# Allow with alternation
# ═══════════════════════════════════════════════════════════════════════════


class TestAllowWithAlternation:
    def test_pipe_allow_matches(self):
        assert agentnanny.matches_allow(
            "Bash", {"command": "git log --oneline"}, ["Bash(git log*|git diff*)"]
        ) is True

    def test_pipe_allow_second_alt(self):
        assert agentnanny.matches_allow(
            "Bash", {"command": "git diff HEAD"}, ["Bash(git log*|git diff*)"]
        ) is True

    def test_pipe_allow_no_match(self):
        assert agentnanny.matches_allow(
            "Bash", {"command": "git push --force"}, ["Bash(git log*|git diff*)"]
        ) is False


# ═══════════════════════════════════════════════════════════════════════════
# Audit log rotation
# ═══════════════════════════════════════════════════════════════════════════


class TestAuditLogRotation:
    def test_rotation_when_file_exceeds_max_size(self, tmp_path):
        log_file = tmp_path / "test.log"
        # Write data exceeding max_size
        log_file.write_text("x" * 200)
        cfg = {
            "logging": {
                "audit_log": str(log_file),
                "level": "actions",
                "max_size_bytes": 100,
                "backup_count": 3,
            }
        }
        agentnanny.audit_log("hook", "allowed", "Bash", "test cmd", cfg)
        # Original should have been rotated; .1 backup should exist
        assert Path(f"{log_file}.1").exists()
        # New log file should contain the new entry
        assert log_file.exists()
        content = log_file.read_text()
        assert "test cmd" in content

    def test_backup_count_respected(self, tmp_path):
        log_file = tmp_path / "test.log"
        cfg = {
            "logging": {
                "audit_log": str(log_file),
                "level": "actions",
                "max_size_bytes": 50,
                "backup_count": 2,
            }
        }
        # Generate enough rotations to exceed backup_count
        for i in range(5):
            log_file.write_text("x" * 100)
            agentnanny.audit_log("hook", "allowed", "Bash", f"cmd{i}", cfg)
        # Only .1 and .2 should exist, not .3
        assert Path(f"{log_file}.1").exists()
        assert Path(f"{log_file}.2").exists()
        assert not Path(f"{log_file}.3").exists()

    def test_no_rotation_when_under_max_size(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text("small")
        cfg = {
            "logging": {
                "audit_log": str(log_file),
                "level": "actions",
                "max_size_bytes": 10485760,
                "backup_count": 3,
            }
        }
        agentnanny.audit_log("hook", "allowed", "Bash", "test", cfg)
        assert not Path(f"{log_file}.1").exists()


# ═══════════════════════════════════════════════════════════════════════════
# Prune command
# ═══════════════════════════════════════════════════════════════════════════


class TestPrune:
    def test_prune_removes_expired(self, tmp_path, capsys):
        sess_dir = tmp_path / "sessions"
        sess_dir.mkdir()
        # Expired session
        expired_policy = {
            "scope_id": "be001234",
            "created": (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat(timespec="seconds"),
            "ttl_seconds": 3600,
            "allow_groups": [],
            "allow_tools": [],
            "deny": [],
        }
        (sess_dir / "be001234.json").write_text(json.dumps(expired_policy))
        with patch.object(agentnanny, "SESSION_DIR", sess_dir):
            agentnanny.cmd_prune()
        assert not (sess_dir / "be001234.json").exists()
        out = capsys.readouterr().out
        assert "1" in out

    def test_prune_keeps_valid(self, tmp_path, capsys):
        sess_dir = tmp_path / "sessions"
        sess_dir.mkdir()
        # Valid session (not expired)
        valid_policy = {
            "scope_id": "face1234",
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ttl_seconds": 36000,
            "allow_groups": ["shell"],
            "allow_tools": [],
            "deny": [],
        }
        (sess_dir / "face1234.json").write_text(json.dumps(valid_policy))
        with patch.object(agentnanny, "SESSION_DIR", sess_dir):
            agentnanny.cmd_prune()
        assert (sess_dir / "face1234.json").exists()
        out = capsys.readouterr().out
        assert "0" in out

    def test_prune_no_sessions_dir(self, tmp_path, capsys):
        sess_dir = tmp_path / "nonexistent"
        with patch.object(agentnanny, "SESSION_DIR", sess_dir):
            agentnanny.cmd_prune()
        out = capsys.readouterr().out
        assert "No sessions" in out


# ═══════════════════════════════════════════════════════════════════════════
# Pattern validation on activate
# ═══════════════════════════════════════════════════════════════════════════


class TestPatternValidation:
    def test_invalid_deny_pattern_raises(self):
        cfg = {
            "hooks": {},
            "groups": dict(agentnanny.BUILTIN_GROUPS),
            "profiles": {k: dict(v) for k, v in agentnanny.BUILTIN_PROFILES.items()},
            "logging": {},
            "daemon": {},
        }
        with patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.object(agentnanny, "generate_scope_id", return_value="a0b1c2d3"), \
             patch.object(agentnanny, "save_session_policy"):
            with pytest.raises(ValueError, match="Invalid deny pattern"):
                agentnanny.cmd_activate(None, "shell", None, "[invalid", None)

    def test_valid_deny_pattern_succeeds(self, capsys):
        cfg = {
            "hooks": {},
            "groups": dict(agentnanny.BUILTIN_GROUPS),
            "profiles": {k: dict(v) for k, v in agentnanny.BUILTIN_PROFILES.items()},
            "logging": {},
            "daemon": {},
        }
        with patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.object(agentnanny, "generate_scope_id", return_value="a0b1c2d3"), \
             patch.object(agentnanny, "save_session_policy", return_value=Path("/tmp/fake")):
            agentnanny.cmd_activate(None, "shell", None, "Bash(rm*|dd*)", None)
        out = capsys.readouterr().out
        assert "AGENTNANNY_SCOPE" in out


# ═══════════════════════════════════════════════════════════════════════════
# tomllib usage on Python 3.11+
# ═══════════════════════════════════════════════════════════════════════════


class TestTomlLib:
    def test_tomllib_used_when_available(self, tmp_path):
        config = tmp_path / "config.toml"
        config.write_text('[daemon]\nsession = "test"\n')
        with patch.object(agentnanny, "CONFIG_PATH", config), \
             patch.object(agentnanny, "_user_config_path", return_value=tmp_path / "noexist"), \
             patch.object(agentnanny, "_find_project_config", return_value=None):
            cfg = agentnanny.load_config()
        assert cfg["daemon"]["session"] == "test"

    def test_fallback_to_parse_toml_when_no_tomllib(self, tmp_path):
        config = tmp_path / "config.toml"
        config.write_text('[daemon]\nsession = "fallback"\n')
        with patch.object(agentnanny, "tomllib", None), \
             patch.object(agentnanny, "CONFIG_PATH", config), \
             patch.object(agentnanny, "_user_config_path", return_value=tmp_path / "noexist"), \
             patch.object(agentnanny, "_find_project_config", return_value=None):
            cfg = agentnanny.load_config()
        assert cfg["daemon"]["session"] == "fallback"
# List groups
# ═══════════════════════════════════════════════════════════════════════════


class TestListGroups:
    def test_lists_builtin_groups(self, capsys):
        agentnanny.cmd_list_groups()
        out = capsys.readouterr().out
        assert "filesystem" in out
        assert "shell" in out
        assert "network" in out
        assert "read-only" in out
        assert "Read" in out

    def test_lists_custom_groups(self, capsys):
        cfg = {
            "hooks": {},
            "groups": {
                "filesystem": ["Read", "Write", "Edit", "Glob", "Grep"],
                "custom-dev": ["Bash(pytest*)", "Bash(uv*)"],
            },
            "profiles": {},
            "logging": {},
        }
        with patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_list_groups()
        out = capsys.readouterr().out
        assert "custom-dev" in out
        assert "Bash(pytest*)" in out

    def test_empty_groups(self, capsys):
        cfg = {
            "hooks": {},
            "groups": {},
            "profiles": {},
            "logging": {},
        }
        with patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_list_groups()
        out = capsys.readouterr().out
        assert "No groups configured" in out


# ═══════════════════════════════════════════════════════════════════════════
# Explain
# ═══════════════════════════════════════════════════════════════════════════


class TestExplain:
    def test_explain_active_session(self, tmp_path, capsys):
        scope_id = "ab12cd34"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ttl_seconds": 28800,
            "allow_groups": ["filesystem", "shell"],
            "allow_tools": ["WebFetch"],
            "deny": ["Bash(rm -rf*)"],
        }
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.save_session_policy(policy)
            agentnanny.cmd_explain(scope_id)
        out = capsys.readouterr().out
        assert f"Session: {scope_id}" in out
        assert "Created:" in out
        assert "TTL: 28800s" in out
        assert "remaining" in out
        assert "Groups: filesystem, shell" in out
        assert "Tools: WebFetch" in out
        assert "Deny: Bash(rm -rf*)" in out

    def test_explain_uses_env_scope(self, tmp_path, capsys):
        scope_id = "ef567890"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ttl_seconds": 0,
            "allow_groups": [],
            "allow_tools": ["Bash"],
            "deny": [],
        }
        with patch.object(agentnanny, "SESSION_DIR", tmp_path), \
             patch.dict(os.environ, {"AGENTNANNY_SCOPE": scope_id}):
            agentnanny.save_session_policy(policy)
            agentnanny.cmd_explain(None)
        out = capsys.readouterr().out
        assert f"Session: {scope_id}" in out

    def test_explain_no_session(self, tmp_path, capsys):
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            with pytest.raises(SystemExit):
                agentnanny.cmd_explain("deadbeef")
        err = capsys.readouterr().err
        assert "No active session" in err

    def test_explain_shows_group_expansion(self, tmp_path, capsys):
        scope_id = "aabb1122"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "ttl_seconds": 0,
            "allow_groups": ["filesystem"],
            "allow_tools": [],
            "deny": [],
        }
        with patch.object(agentnanny, "SESSION_DIR", tmp_path):
            agentnanny.save_session_policy(policy)
            agentnanny.cmd_explain(scope_id)
        out = capsys.readouterr().out
        # Should show expanded patterns for the filesystem group
        assert "filesystem ->" in out
        assert "Read" in out
        assert "Write" in out
        assert "Edit" in out
# evaluate_policy — pure dry-run evaluation
# ═══════════════════════════════════════════════════════════════════════════


class TestEvaluatePolicy:
    def test_global_deny_blocks(self):
        cfg = {"hooks": {"deny": ["Bash"]}}
        verdict, reason = agentnanny.evaluate_policy("Bash", {}, cfg)
        assert verdict == "deny"
        assert "global deny" in reason

    def test_session_deny_blocks(self, tmp_path):
        scope_id = "ab12cd34"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": 0,
            "allow_tools": ["Bash"],
            "allow_groups": [],
            "deny": ["Bash(rm*)"],
        }
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(parents=True)
        (session_dir / f"{scope_id}.json").write_text(json.dumps(policy))
        cfg = {"hooks": {}}
        with patch.object(agentnanny, "SESSION_DIR", session_dir):
            verdict, reason = agentnanny.evaluate_policy(
                "Bash", {"command": "rm -rf /"}, cfg, scope_id,
            )
        assert verdict == "deny"
        assert "session deny" in reason

    def test_session_allow_permits(self, tmp_path):
        scope_id = "aa11bb22"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": 0,
            "allow_tools": ["Read", "Glob"],
            "allow_groups": [],
            "deny": [],
        }
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(parents=True)
        (session_dir / f"{scope_id}.json").write_text(json.dumps(policy))
        cfg = {"hooks": {}}
        with patch.object(agentnanny, "SESSION_DIR", session_dir):
            verdict, reason = agentnanny.evaluate_policy("Read", {}, cfg, scope_id)
        assert verdict == "allow"
        assert "allowed by session" in reason

    def test_passthrough_no_scope(self):
        cfg = {"hooks": {}}
        verdict, reason = agentnanny.evaluate_policy("Bash", {}, cfg, None)
        assert verdict == "passthrough"
        assert "no scope" in reason

    def test_passthrough_not_in_allow(self, tmp_path):
        scope_id = "cc33dd44"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": 0,
            "allow_tools": ["Read"],
            "allow_groups": [],
            "deny": [],
        }
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(parents=True)
        (session_dir / f"{scope_id}.json").write_text(json.dumps(policy))
        cfg = {"hooks": {}}
        with patch.object(agentnanny, "SESSION_DIR", session_dir):
            verdict, reason = agentnanny.evaluate_policy("Bash", {}, cfg, scope_id)
        assert verdict == "passthrough"
        assert "not in session allow" in reason

    def test_global_deny_trumps_session_allow(self, tmp_path):
        scope_id = "ee55ff66"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": 0,
            "allow_tools": ["Bash"],
            "allow_groups": [],
            "deny": [],
        }
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(parents=True)
        (session_dir / f"{scope_id}.json").write_text(json.dumps(policy))
        cfg = {"hooks": {"deny": ["Bash"]}}
        with patch.object(agentnanny, "SESSION_DIR", session_dir):
            verdict, reason = agentnanny.evaluate_policy("Bash", {}, cfg, scope_id)
        assert verdict == "deny"
        assert "global deny" in reason


# ═══════════════════════════════════════════════════════════════════════════
# cmd_test_policy — CLI wrapper
# ═══════════════════════════════════════════════════════════════════════════


class TestCmdTestPolicy:
    def test_cli_deny_output(self, capsys):
        cfg = {"hooks": {"deny": ["Bash"]}}
        with patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_test_policy("Bash", "{}", None)
        out = capsys.readouterr().out
        assert "deny" in out

    def test_cli_allow_output(self, tmp_path, capsys):
        scope_id = "11aa22bb"
        policy = {
            "scope_id": scope_id,
            "created": datetime.now(timezone.utc).isoformat(),
            "ttl_seconds": 0,
            "allow_tools": ["Read"],
            "allow_groups": [],
            "deny": [],
        }
        session_dir = tmp_path / "sessions"
        session_dir.mkdir(parents=True)
        (session_dir / f"{scope_id}.json").write_text(json.dumps(policy))
        cfg = {"hooks": {}}
        with patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.object(agentnanny, "SESSION_DIR", session_dir):
            agentnanny.cmd_test_policy("Read", "{}", scope_id)
        out = capsys.readouterr().out
        assert "allow" in out

    def test_cli_passthrough_output(self, capsys):
        cfg = {"hooks": {}}
        with patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.dict(os.environ, {}, clear=False):
            # Ensure no AGENTNANNY_SCOPE in env
            env = os.environ.copy()
            env.pop("AGENTNANNY_SCOPE", None)
            with patch.dict(os.environ, env, clear=True):
                agentnanny.cmd_test_policy("Bash", "{}", None)
        out = capsys.readouterr().out
        assert "passthrough" in out
# show_log
# ═══════════════════════════════════════════════════════════════════════════


SAMPLE_LOG_LINES = [
    "2026-01-01T00:00:00+00:00\thook\tallowed\tBash\tcommand=ls\n",
    "2026-01-01T00:00:01+00:00\thook\tdenied\tWrite\tpath=/etc/passwd\n",
    "2026-01-01T00:00:02+00:00\tdaemon\tapproved\tcontinue\tpane=%0\n",
    "2026-01-01T00:00:03+00:00\thook\tallowed\tRead\tpath=foo.py\n",
    "2026-01-01T00:00:04+00:00\thook\tdenied\tBash\tcommand=rm -rf /\n",
]


class TestShowLog:
    def _write_log(self, tmp_path: Path, lines: list[str] | None = None) -> str:
        log_file = tmp_path / "test.log"
        log_file.write_text("".join(lines or SAMPLE_LOG_LINES), encoding="utf-8")
        return str(log_file)

    def test_raw_format(self, tmp_path, capsys):
        log_path = self._write_log(tmp_path)
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": log_path}}):
            agentnanny.show_log(output_format="raw")
        out = capsys.readouterr().out
        assert "Bash" in out
        assert "\t" in out
        lines = [l for l in out.strip().splitlines() if l]
        assert len(lines) == 5

    def test_json_format(self, tmp_path, capsys):
        log_path = self._write_log(tmp_path)
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": log_path}}):
            agentnanny.show_log(output_format="json")
        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 5
        assert data[0]["timestamp"] == "2026-01-01T00:00:00+00:00"
        assert data[0]["source"] == "hook"
        assert data[0]["action"] == "allowed"
        assert data[0]["tool_name"] == "Bash"
        assert data[0]["detail"] == "command=ls"

    def test_table_format(self, tmp_path, capsys):
        log_path = self._write_log(tmp_path)
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": log_path}}):
            agentnanny.show_log(output_format="table")
        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        # Header + separator + 5 data rows
        assert len(lines) == 7
        assert "TIMESTAMP" in lines[0]
        assert "SOURCE" in lines[0]
        assert "ACTION" in lines[0]
        assert "TOOL" in lines[0]
        assert "DETAIL" in lines[0]
        assert "---" in lines[1]

    def test_filter_by_tool(self, tmp_path, capsys):
        log_path = self._write_log(tmp_path)
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": log_path}}):
            agentnanny.show_log(output_format="json", filter_tool="Bash")
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 2
        assert all(r["tool_name"] == "Bash" for r in data)

    def test_filter_by_action(self, tmp_path, capsys):
        log_path = self._write_log(tmp_path)
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": log_path}}):
            agentnanny.show_log(output_format="json", filter_action="denied")
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 2
        assert all(r["action"] == "denied" for r in data)

    def test_combined_filters(self, tmp_path, capsys):
        log_path = self._write_log(tmp_path)
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": log_path}}):
            agentnanny.show_log(output_format="json", filter_tool="Bash", filter_action="denied")
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 1
        assert data[0]["tool_name"] == "Bash"
        assert data[0]["action"] == "denied"

    def test_lines_limit(self, tmp_path, capsys):
        log_path = self._write_log(tmp_path)
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": log_path}}):
            agentnanny.show_log(lines_count=2, output_format="json")
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 2
        # Should be the last 2 entries
        assert data[0]["tool_name"] == "Read"
        assert data[1]["tool_name"] == "Bash"

    def test_empty_log(self, tmp_path, capsys):
        # Missing log file
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": str(tmp_path / "nonexistent.log")}}):
            agentnanny.show_log()
        out = capsys.readouterr().out
        assert "No log file" in out

        # Empty log file
        empty_log = tmp_path / "empty.log"
        empty_log.write_text("", encoding="utf-8")
        with patch.object(agentnanny, "load_config", return_value={"logging": {"audit_log": str(empty_log)}}):
            agentnanny.show_log()
        out = capsys.readouterr().out
        assert "No matching log entries" in out
# PostToolUse hook
# ═══════════════════════════════════════════════════════════════════════════


class TestPostToolUseHook:
    def _make_cfg(self, **ctx_overrides):
        cfg = {
            "hooks": {},
            "logging": {"audit_log": os.devnull, "level": "all"},
            "context": {},
        }
        cfg["context"].update(ctx_overrides)
        return cfg

    def _run_post_hook(self, event, tmp_path, cfg=None, status=None):
        """Run handle_post_hook with a real tmp_path for status.json."""
        cfg = cfg or self._make_cfg()
        stdin = StringIO(json.dumps(event))
        stdout = StringIO()

        status_dir = tmp_path / ".claude"
        status_dir.mkdir(parents=True, exist_ok=True)
        status_file = status_dir / "status.json"
        if status is not None:
            status_file.write_text(json.dumps(status), encoding="utf-8")

        with patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch("pathlib.Path.home", return_value=tmp_path):
            agentnanny.handle_post_hook()

        raw = stdout.getvalue()
        if not raw:
            return None
        return json.loads(raw)

    def test_post_hook_logs_execution(self, tmp_path):
        event = {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}}
        cfg = self._make_cfg()

        stdin = StringIO(json.dumps(event))
        stdout = StringIO()

        with patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch("pathlib.Path.home", return_value=tmp_path), \
             patch.object(agentnanny, "audit_log") as mock_log:
            agentnanny.handle_post_hook()

        mock_log.assert_called_once()
        call_args = mock_log.call_args
        assert call_args[0][0] == "hook"
        assert call_args[0][1] == "executed"
        assert call_args[0][2] == "Read"

    def test_post_hook_no_status_file(self, tmp_path):
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        result = self._run_post_hook(event, tmp_path)
        assert result is None

    def test_post_hook_context_warning(self, tmp_path):
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        result = self._run_post_hook(event, tmp_path, status={"contextPercent": 65})
        assert result is not None
        msg = result["hookSpecificOutput"]["message"]
        assert "WARNING" in msg
        assert "65%" in msg

    def test_post_hook_context_critical(self, tmp_path):
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        result = self._run_post_hook(event, tmp_path, status={"contextPercent": 80})
        assert result is not None
        msg = result["hookSpecificOutput"]["message"]
        assert "CRITICAL" in msg
        assert "80%" in msg

    def test_post_hook_context_below_threshold(self, tmp_path):
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        result = self._run_post_hook(event, tmp_path, status={"contextPercent": 30})
        assert result is None

    def test_post_hook_custom_thresholds(self, tmp_path):
        event = {"tool_name": "Bash", "tool_input": {"command": "ls"}}
        cfg = self._make_cfg(warn_percent=50, critical_percent=70)
        result = self._run_post_hook(event, tmp_path, cfg=cfg, status={"contextPercent": 55})
        assert result is not None
        msg = result["hookSpecificOutput"]["message"]
        assert "WARNING" in msg
        assert "55%" in msg

    def test_install_registers_post_hook(self, tmp_path):
        settings_file = tmp_path / "settings.json"
        settings_file.write_text("{}", encoding="utf-8")

        with patch.object(agentnanny, "SETTINGS_PATH", settings_file):
            agentnanny.install_hooks()

        settings = json.loads(settings_file.read_text(encoding="utf-8"))
        post = settings["hooks"]["PostToolUse"]
        assert len(post) == 1
        assert "agentnanny" in post[0]["hooks"][0]["command"]
        assert "post-hook" in post[0]["hooks"][0]["command"]


# ═══════════════════════════════════════════════════════════════════════════
# Codex CLI integration
# ═══════════════════════════════════════════════════════════════════════════


class TestSerializeTomlValue:
    def test_string(self):
        assert agentnanny._serialize_toml_value("hello") == '"hello"'

    def test_bool_true(self):
        assert agentnanny._serialize_toml_value(True) == "true"

    def test_bool_false(self):
        assert agentnanny._serialize_toml_value(False) == "false"

    def test_int(self):
        assert agentnanny._serialize_toml_value(42) == "42"

    def test_list_of_strings(self):
        result = agentnanny._serialize_toml_value(["a", "b", "c"])
        assert result == '["a", "b", "c"]'

    def test_empty_list(self):
        assert agentnanny._serialize_toml_value([]) == "[]"

    def test_unsupported_type(self):
        with pytest.raises(TypeError):
            agentnanny._serialize_toml_value({"key": "val"})


class TestPatchCodexConfig:
    def test_creates_config_file(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._patch_codex_config({"approval_policy": "on-request"})

        assert config_path.exists()
        content = config_path.read_text(encoding="utf-8")
        assert 'approval_policy = "on-request"' in content

    def test_preserves_existing_keys(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('model = "o3"\n', encoding="utf-8")

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._patch_codex_config({"approval_policy": "never"})

        content = config_path.read_text(encoding="utf-8")
        assert 'model = "o3"' in content
        assert 'approval_policy = "never"' in content

    def test_replaces_existing_key(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('approval_policy = "on-request"\n', encoding="utf-8")

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._patch_codex_config({"approval_policy": "never"})

        content = config_path.read_text(encoding="utf-8")
        assert 'approval_policy = "never"' in content
        assert "on-request" not in content

    def test_preserves_comments(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('# My config\nmodel = "o3"\n', encoding="utf-8")

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._patch_codex_config({"notify": ["python3", "agentnanny.py"]})

        content = config_path.read_text(encoding="utf-8")
        assert "# My config" in content
        assert 'notify = ["python3", "agentnanny.py"]' in content

    def test_writes_list_value(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._patch_codex_config({"notify": ["cmd", "arg1", "arg2"]})

        content = config_path.read_text(encoding="utf-8")
        assert 'notify = ["cmd", "arg1", "arg2"]' in content

    def test_inserts_new_keys_before_first_table(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('model = "o3"\n[tui]\nstatus_line = []\n', encoding="utf-8")

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._patch_codex_config({"notify": ["python3", "agentnanny.py"]})

        content = config_path.read_text(encoding="utf-8")
        assert content.index('notify = ["python3", "agentnanny.py"]') < content.index("[tui]")

    def test_relocates_misplaced_nested_key(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text(
            'model = "o3"\n[tui]\nnotify = ["bad"]\nstatus_line = []\n',
            encoding="utf-8",
        )

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._patch_codex_config({"notify": ["python3", "agentnanny.py"]})

        content = config_path.read_text(encoding="utf-8")
        assert 'notify = ["bad"]' not in content
        assert content.index('notify = ["python3", "agentnanny.py"]') < content.index("[tui]")


class TestRemoveCodexConfigKeys:
    def test_removes_key(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('model = "o3"\napproval_policy = "never"\n', encoding="utf-8")

        with patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            result = agentnanny._remove_codex_config_keys(["approval_policy"])

        assert result is True
        content = config_path.read_text(encoding="utf-8")
        assert "approval_policy" not in content
        assert 'model = "o3"' in content

    def test_no_file_returns_false(self, tmp_path):
        config_path = tmp_path / "nonexistent.toml"
        with patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            result = agentnanny._remove_codex_config_keys(["approval_policy"])
        assert result is False

    def test_key_not_present(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('model = "o3"\n', encoding="utf-8")

        with patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            result = agentnanny._remove_codex_config_keys(["approval_policy"])
        assert result is False


class TestPatternsToCodexRules:
    def test_deny_bash_pattern(self):
        rules = agentnanny._patterns_to_codex_rules(["Bash(rm -rf /*)"], "forbidden")
        assert 'pattern=["rm", "-rf", "/"]' in rules
        assert 'decision="forbidden"' in rules
        assert 'justification="blocked by agentnanny"' in rules

    def test_deny_alternation_pattern(self):
        rules = agentnanny._patterns_to_codex_rules(["Bash(curl*|wget*)"], "forbidden")
        assert 'pattern=["curl"]' in rules
        assert 'pattern=["wget"]' in rules

    def test_non_bash_skipped(self):
        rules = agentnanny._patterns_to_codex_rules(["WebFetch", "Write"], "forbidden")
        assert rules.strip() == ""

    def test_deny_git_push_force(self):
        rules = agentnanny._patterns_to_codex_rules(["Bash(git push --force*)"], "forbidden")
        assert 'pattern=["git", "push", "--force"]' in rules
        assert 'decision="forbidden"' in rules

    def test_deny_mixed_patterns(self):
        rules = agentnanny._patterns_to_codex_rules([
            "Bash(rm -rf /*)",
            "WebFetch",
            "Bash(DROP TABLE*)",
        ], "forbidden")
        assert 'pattern=["rm", "-rf", "/"]' in rules
        assert 'pattern=["DROP", "TABLE"]' in rules
        assert "WebFetch" not in rules

    def test_allow_bash_pattern(self):
        rules = agentnanny._patterns_to_codex_rules(["Bash(ls*)"], "allow")
        assert 'pattern=["ls"]' in rules
        assert 'decision="allow"' in rules
        assert 'justification="allowed by agentnanny"' in rules

    def test_allow_git_commands(self):
        rules = agentnanny._patterns_to_codex_rules([
            "Bash(git log*)", "Bash(git diff*)", "Bash(git show*)",
        ], "allow")
        assert 'pattern=["git", "log"]' in rules
        assert 'pattern=["git", "diff"]' in rules
        assert 'pattern=["git", "show"]' in rules

    def test_allow_non_bash_skipped(self):
        rules = agentnanny._patterns_to_codex_rules(["Read", "Glob", "Grep"], "allow")
        assert rules.strip() == ""

    def test_allow_alternation(self):
        rules = agentnanny._patterns_to_codex_rules(["Bash(cat*|head*)"], "allow")
        assert 'pattern=["cat"]' in rules
        assert 'pattern=["head"]' in rules


class TestWriteRemoveCodexRules:
    def test_write_creates_file(self, tmp_path):
        codex_home = tmp_path / ".codex"
        with patch.object(agentnanny, "CODEX_HOME", codex_home):
            path = agentnanny._write_codex_rules("abc12345", "# test rules\n")

        assert path.exists()
        assert path.name == "agentnanny-abc12345.rules"
        assert path.read_text(encoding="utf-8") == "# test rules\n"

    def test_remove_deletes_file(self, tmp_path):
        codex_home = tmp_path / ".codex"
        rules_dir = codex_home / "rules"
        rules_dir.mkdir(parents=True)
        rules_file = rules_dir / "agentnanny-abc12345.rules"
        rules_file.write_text("# test\n", encoding="utf-8")

        with patch.object(agentnanny, "CODEX_HOME", codex_home):
            result = agentnanny._remove_codex_rules("abc12345")

        assert result is True
        assert not rules_file.exists()

    def test_remove_nonexistent(self, tmp_path):
        codex_home = tmp_path / ".codex"
        with patch.object(agentnanny, "CODEX_HOME", codex_home):
            result = agentnanny._remove_codex_rules("abc12345")
        assert result is False

    def test_remove_all(self, tmp_path):
        codex_home = tmp_path / ".codex"
        rules_dir = codex_home / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "agentnanny-abc12345.rules").write_text("# 1\n")
        (rules_dir / "agentnanny-def67890.rules").write_text("# 2\n")
        (rules_dir / "other.rules").write_text("# 3\n")

        with patch.object(agentnanny, "CODEX_HOME", codex_home):
            count = agentnanny._remove_all_codex_rules()

        assert count == 2
        assert (rules_dir / "other.rules").exists()


class TestInstallUninstallCodex:
    def test_install_creates_notify(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny.install_codex_hooks()

        content = config_path.read_text(encoding="utf-8")
        assert "agentnanny" in content
        assert "codex-hook" in content
        assert content.startswith("notify = [")

    def test_install_idempotent(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny.install_codex_hooks()
            with pytest.raises(SystemExit):
                agentnanny.install_codex_hooks()

    def test_install_preserves_existing(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('model = "o3"\n', encoding="utf-8")

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny.install_codex_hooks()

        content = config_path.read_text(encoding="utf-8")
        assert 'model = "o3"' in content
        assert "agentnanny" in content

    def test_uninstall_removes_notify(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny.install_codex_hooks()
            agentnanny.uninstall_codex_hooks()

        content = config_path.read_text(encoding="utf-8")
        assert "notify" not in content

    def test_uninstall_no_config_exits(self, tmp_path):
        config_path = tmp_path / "nonexistent.toml"
        with patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            with pytest.raises(SystemExit):
                agentnanny.uninstall_codex_hooks()

    def test_uninstall_removes_rules_files(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        rules_dir = codex_home / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "agentnanny-abc12345.rules").write_text("# test\n")

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny.install_codex_hooks()
            agentnanny.uninstall_codex_hooks()

        assert not (rules_dir / "agentnanny-abc12345.rules").exists()


class TestCodexHook:
    def test_logs_shell_command(self, tmp_path):
        event = {
            "tool_name": "shell_command",
            "tool_input": {"command": ["ls", "-la", "/tmp"]},
        }
        stdin = StringIO(json.dumps(event))
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}

        with patch.object(sys, "stdin", stdin), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.object(agentnanny, "audit_log") as mock_log:
            agentnanny.handle_codex_hook()

        mock_log.assert_called_once()
        assert mock_log.call_args[0][0] == "codex-hook"
        assert mock_log.call_args[0][1] == "executed"
        assert mock_log.call_args[0][2] == "shell_command"
        assert "ls -la /tmp" in mock_log.call_args[0][3]

    def test_handles_string_command(self, tmp_path):
        event = {
            "tool_name": "apply_patch",
            "tool_input": {"command": "patch content"},
        }
        stdin = StringIO(json.dumps(event))
        cfg = {"hooks": {}, "logging": {"audit_log": os.devnull, "level": "all"}}

        with patch.object(sys, "stdin", stdin), \
             patch.object(agentnanny, "load_config", return_value=cfg), \
             patch.object(agentnanny, "audit_log") as mock_log:
            agentnanny.handle_codex_hook()

        assert mock_log.call_args[0][3] == "patch content"


class TestApplyRemoveCodexSession:
    def _make_cfg(self):
        return {
            "hooks": {},
            "groups": dict(agentnanny.BUILTIN_GROUPS),
            "profiles": {k: dict(v) for k, v in agentnanny.BUILTIN_PROFILES.items()},
            "logging": {"audit_log": os.devnull},
        }

    def test_apply_sets_approval_policy(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        cfg = self._make_cfg()
        policy = {
            "_profile_name": "safe-dev",
            "deny": [],
            "allow_groups": ["filesystem", "safe-shell"],
            "allow_tools": [],
        }

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._apply_codex_session(policy, cfg, "abc12345")

        content = config_path.read_text(encoding="utf-8")
        assert 'approval_policy = "unless-trusted"' in content

    def test_apply_generates_deny_rules(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        cfg = self._make_cfg()
        policy = {
            "_profile_name": "full-dev",
            "deny": ["Bash(rm -rf /*)", "Bash(git push --force*)"],
            "allow_groups": ["filesystem", "shell"],
            "allow_tools": [],
        }

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._apply_codex_session(policy, cfg, "abc12345")

        rules_path = codex_home / "rules" / "agentnanny-abc12345.rules"
        assert rules_path.exists()
        content = rules_path.read_text(encoding="utf-8")
        assert 'pattern=["rm", "-rf", "/"]' in content
        assert 'pattern=["git", "push", "--force"]' in content
        assert 'decision="forbidden"' in content

    def test_apply_generates_allow_rules(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        cfg = self._make_cfg()
        policy = {
            "_profile_name": "reviewer",
            "deny": [],
            "allow_groups": ["review-shell"],
            "allow_tools": [],
        }

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._apply_codex_session(policy, cfg, "abc12345")

        rules_path = codex_home / "rules" / "agentnanny-abc12345.rules"
        assert rules_path.exists()
        content = rules_path.read_text(encoding="utf-8")
        assert 'pattern=["git", "log"]' in content
        assert 'decision="allow"' in content

    def test_remove_cleans_up(self, tmp_path):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('approval_policy = "never"\n', encoding="utf-8")
        rules_dir = codex_home / "rules"
        rules_dir.mkdir()
        (rules_dir / "agentnanny-abc12345.rules").write_text("# test\n")

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._remove_codex_session("abc12345")

        assert not (rules_dir / "agentnanny-abc12345.rules").exists()
        content = config_path.read_text(encoding="utf-8")
        assert "approval_policy" not in content

    def test_unknown_profile_defaults_on_request(self, tmp_path):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        cfg = self._make_cfg()
        policy = {
            "deny": [],
            "allow_groups": [],
            "allow_tools": ["Bash"],
        }

        with patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            agentnanny._apply_codex_session(policy, cfg, "abc12345")

        content = config_path.read_text(encoding="utf-8")
        assert 'approval_policy = "on-request"' in content


class TestActivateDeactivateCodex:
    def test_activate_codex_target(self, tmp_path, capsys):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "config.toml"
        cfg = {
            "hooks": {},
            "groups": dict(agentnanny.BUILTIN_GROUPS),
            "profiles": {k: dict(v) for k, v in agentnanny.BUILTIN_PROFILES.items()},
            "logging": {"audit_log": os.devnull},
        }
        with patch.object(agentnanny, "SESSION_DIR", tmp_path / "sessions"), \
             patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path), \
             patch.object(agentnanny, "load_config", return_value=cfg):
            agentnanny.cmd_activate("safe-dev", None, None, None, "8h", target="codex")

        out = capsys.readouterr().out
        assert "export AGENTNANNY_SCOPE=" in out
        assert config_path.exists()
        content = config_path.read_text(encoding="utf-8")
        assert "unless-trusted" in content

    def test_deactivate_codex_target(self, tmp_path, capsys):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('approval_policy = "never"\n', encoding="utf-8")
        rules_dir = codex_home / "rules"
        rules_dir.mkdir()
        (rules_dir / "agentnanny-dea01234.rules").write_text("# test\n")

        with patch.object(agentnanny, "SESSION_DIR", tmp_path / "sessions"), \
             patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path):
            (tmp_path / "sessions").mkdir()
            agentnanny.save_session_policy({
                "scope_id": "dea01234",
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "ttl_seconds": 0,
                "allow_groups": [],
                "allow_tools": [],
                "deny": [],
            })
            agentnanny.cmd_deactivate("dea01234", target="codex")

        out = capsys.readouterr().out
        assert "unset AGENTNANNY_SCOPE" in out
        assert not (rules_dir / "agentnanny-dea01234.rules").exists()


class TestCodexApprovalMap:
    def test_all_builtin_profiles_mapped(self):
        for name in agentnanny.BUILTIN_PROFILES:
            assert name in agentnanny.CODEX_APPROVAL_MAP, \
                f"Profile {name!r} missing from CODEX_APPROVAL_MAP"

    def test_values_are_valid_codex_policies(self):
        valid = {"never", "on-failure", "on-request", "unless-trusted"}
        for name, policy in agentnanny.CODEX_APPROVAL_MAP.items():
            assert policy in valid, f"{name} maps to invalid policy {policy!r}"


class TestBuildPolicy:
    def test_includes_profile_name(self):
        cfg = {
            "hooks": {},
            "groups": dict(agentnanny.BUILTIN_GROUPS),
            "profiles": {k: dict(v) for k, v in agentnanny.BUILTIN_PROFILES.items()},
        }
        policy, scope_id = agentnanny._build_policy("safe-dev", None, None, None, "1h", cfg)
        assert policy["_profile_name"] == "safe-dev"
        assert policy["ttl_seconds"] == 3600

    def test_no_profile_no_key(self):
        cfg = {"hooks": {}, "groups": {}, "profiles": {}}
        policy, _ = agentnanny._build_policy(None, None, "Bash", None, "0", cfg)
        assert "_profile_name" not in policy

    def test_merges_groups_and_tools(self):
        cfg = {
            "hooks": {},
            "groups": {"shell": ["Bash"], "read-only": ["Read", "Glob", "Grep"]},
            "profiles": {},
        }
        policy, _ = agentnanny._build_policy(None, "shell,read-only", "Write", None, "0", cfg)
        assert policy["allow_groups"] == ["shell", "read-only"]
        assert policy["allow_tools"] == ["Write"]


class TestCodexStatus:
    def test_shows_codex_section(self, tmp_path, capsys):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text(
            'notify = ["python3", "agentnanny.py", "codex-hook"]\n'
            'approval_policy = "never"\n',
            encoding="utf-8",
        )

        with patch.object(agentnanny, "SETTINGS_PATH", tmp_path / "nonexistent.json"), \
             patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path), \
             patch.object(agentnanny, "SESSION_DIR", tmp_path / "sessions"), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            agentnanny.show_status()

        err = capsys.readouterr().out
        assert "Codex CLI" in err
        assert "Notify hook installed: yes" in err
        assert "Approval policy: never" in err

    def test_shows_codex_not_installed(self, tmp_path, capsys):
        codex_home = tmp_path / ".codex"
        config_path = codex_home / "nonexistent.toml"

        with patch.object(agentnanny, "SETTINGS_PATH", tmp_path / "nonexistent.json"), \
             patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path), \
             patch.object(agentnanny, "SESSION_DIR", tmp_path / "sessions"), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            agentnanny.show_status()

        err = capsys.readouterr().out
        assert "Notify hook installed: no" in err

    def test_shows_rules_count(self, tmp_path, capsys):
        codex_home = tmp_path / ".codex"
        codex_home.mkdir()
        config_path = codex_home / "config.toml"
        config_path.write_text('model = "o3"\n', encoding="utf-8")
        rules_dir = codex_home / "rules"
        rules_dir.mkdir()
        (rules_dir / "agentnanny-abc12345.rules").write_text("# 1\n")
        (rules_dir / "agentnanny-def67890.rules").write_text("# 2\n")

        with patch.object(agentnanny, "SETTINGS_PATH", tmp_path / "nonexistent.json"), \
             patch.object(agentnanny, "CODEX_HOME", codex_home), \
             patch.object(agentnanny, "CODEX_CONFIG_PATH", config_path), \
             patch.object(agentnanny, "SESSION_DIR", tmp_path / "sessions"), \
             patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AGENTNANNY_SCOPE", None)
            agentnanny.show_status()

        err = capsys.readouterr().out
        assert "Exec policy rules: 2 file(s)" in err

#!/usr/bin/env python3
"""PreToolUse hook: keep coding agents out of human-owned files.

The paths in `.claude/protected-paths.txt` are written by a human only: the eval corpus and its
lock, the gate thresholds, and the agent's own guardrails. This hook is layer 1 of 3. CODEOWNERS
review and the corpus hash test in CI are layers 2 and 3, so anything that slips past here is
caught before merge rather than shipped.

Fails closed. If the config or the hook input cannot be read, the tool call is blocked. A shell
segment that names a protected path is allowed only when it starts with a known read-only command
and has no output redirect. This is an allowlist on purpose: a list of "write-like" commands can
never be complete. Known gap, covered by layers 2 and 3: a program that writes a protected file
without naming it on the command line.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent
CONFIG_PATH = HOOK_DIR.parent / "protected-paths.txt"

FILE_TOOL_PATH_KEYS = {
    "Edit": "file_path",
    "Write": "file_path",
    "MultiEdit": "file_path",
    "NotebookEdit": "notebook_path",
}
SHELL_TOOLS = frozenset({"Bash", "PowerShell"})

# Lower-case command prefixes that cannot modify the files they name. `git add` only stages.
# `cd` is deliberately absent: `cd eval/corpus && rm x` would hide the path from later segments.
READ_ONLY_PREFIXES = (
    "cat", "head", "tail", "less", "more", "wc", "grep", "rg", "diff", "ls", "stat", "file",
    "sha256sum", "shasum", "md5sum",
    "git diff", "git log", "git show", "git status", "git blame", "git ls-files", "git add",
    "get-content", "gc", "select-string", "get-filehash", "get-childitem", "test-path",
    "python -m pytest", "pytest", "uv run pytest", "uv run python -m pytest",
    "python scripts/verify.py", "uv run python scripts/verify.py",
    "python -m unittest", "python eval/run_eval.py",
    "python -m firewall.cli replay", "python -m firewall.cli verify-audit",
)
SEGMENT_SEPARATORS = re.compile(r"&&|\|\||[;|\n]")
# Stream merges and discards are not writes to a named file.
HARMLESS_REDIRECTS = re.compile(r"\d?>&\d|\d?>\s*/dev/null|\d?>\s*\$null|\d?>\s*nul\b")


def load_patterns(config_path: Path) -> list[str]:
    """Read protected globs (repo-relative, `**` = anything below). Empty config is an error."""
    lines = config_path.read_text(encoding="utf-8").splitlines()
    patterns = [
        line.strip().replace("\\", "/").lower()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not patterns:
        raise ValueError(f"{config_path} lists no protected paths")
    return patterns


def matching_pattern(rel_path: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        # fnmatch's `*` already crosses `/`, so `**` needs no special handling beyond this.
        if fnmatch.fnmatchcase(rel_path, pattern.replace("**", "*")):
            return pattern
    return None


def relative_to_project(raw_path: str, project_dir: Path) -> str | None:
    """Repo-relative, lower-case, forward-slash path; None when the path is outside the repo."""
    path = Path(raw_path)
    if not path.is_absolute():
        path = project_dir / path
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(project_dir))
    except ValueError:  # different drive on Windows
        return None
    rel = rel.replace("\\", "/").lower()
    if rel == ".." or rel.startswith("../"):
        return None
    return rel


def literal_stem(pattern: str) -> str:
    """The part of a glob that must appear verbatim in a command that names a matching path."""
    return pattern.split("*", 1)[0].rstrip("/")


def is_read_only(segment: str) -> bool:
    return any(segment == p or segment.startswith(p + " ") for p in READ_ONLY_PREFIXES)


def check_shell(command: str, patterns: list[str]) -> str | None:
    text = command.replace("\\", "/").lower()
    stems = [stem for stem in (literal_stem(p) for p in patterns) if stem]
    for raw_segment in SEGMENT_SEPARATORS.split(text):
        segment = raw_segment.strip()
        hits = [stem for stem in stems if stem in segment]
        if not hits:
            continue
        if segment.startswith("rtk "):  # RTK's Bash hook prefixes commands; judge the real one
            segment = segment[len("rtk ") :].lstrip()
        writes = ">" in HARMLESS_REDIRECTS.sub("", segment)
        if writes or not is_read_only(segment):
            return (
                f"Blocked by protect_paths: shell command touches protected path '{hits[0]}' "
                "(human-owned, AGENTS.md §2.4). Only read-only commands may name it. "
                "Ask the human to make this change."
            )
    return None


def check_file_tool(
    tool_name: str, tool_input: dict[str, object], project_dir: Path, patterns: list[str]
) -> str | None:
    key = FILE_TOOL_PATH_KEYS[tool_name]
    raw_path = tool_input.get(key)
    if not isinstance(raw_path, str) or not raw_path:
        return f"Blocked by protect_paths: {tool_name} call has no '{key}' (fail closed)."
    rel = relative_to_project(raw_path, project_dir)
    if rel is None:
        return None
    pattern = matching_pattern(rel, patterns)
    if pattern is None:
        return None
    return (
        f"Blocked by protect_paths: '{rel}' matches protected pattern '{pattern}' "
        "(human-owned, AGENTS.md §2.4). Ask the human to make this change."
    )


def decide(
    tool_name: str, tool_input: dict[str, object], project_dir: Path, config_path: Path
) -> str | None:
    """Return a denial reason, or None to let the tool call proceed."""
    if tool_name not in FILE_TOOL_PATH_KEYS and tool_name not in SHELL_TOOLS:
        return None
    patterns = load_patterns(config_path)
    if tool_name in SHELL_TOOLS:
        command = tool_input.get("command")
        if not isinstance(command, str):
            return f"Blocked by protect_paths: {tool_name} call has no command (fail closed)."
        return check_shell(command, patterns)
    return check_file_tool(tool_name, tool_input, project_dir, patterns)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        project_dir = Path(
            os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or HOOK_DIR.parent.parent
        )
        tool_input = payload.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            raise TypeError("tool_input is not an object")
        reason = decide(str(payload.get("tool_name", "")), tool_input, project_dir, CONFIG_PATH)
    except Exception as exc:  # Fail closed: a broken guard must block, never wave through.
        print(f"protect_paths hook error, blocking tool call: {exc}", file=sys.stderr)
        return 2
    if reason:
        decision = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
        print(json.dumps(decision))
    return 0


if __name__ == "__main__":
    sys.exit(main())

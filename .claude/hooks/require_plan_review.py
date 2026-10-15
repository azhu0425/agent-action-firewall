#!/usr/bin/env python3
"""PreToolUse hook for ExitPlanMode: block until /review-plan has run in this session.

It looks for an actual invocation in the transcript: either a Skill tool call for `review-plan`
or the human typing the slash command. A plain substring search would pass any plan that merely
mentions review-plan. The hook fails closed when the transcript cannot be read. If that ever
deadlocks a session, a human removes the hook from .claude/settings.json; an agent must not.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path

SLASH_COMMAND_MARKER = "<command-name>/review-plan</command-name>"


def _is_review_plan_skill(block: dict[str, object]) -> bool:
    if block.get("type") != "tool_use" or block.get("name") != "Skill":
        return False
    tool_input = block.get("input")
    skill = str(tool_input.get("skill", "")) if isinstance(tool_input, dict) else ""
    return skill == "review-plan" or skill.endswith(":review-plan")


def review_plan_invoked(transcript_lines: Iterable[str]) -> bool:
    for line in transcript_lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = entry.get("message") if isinstance(entry, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            if SLASH_COMMAND_MARKER in content:
                return True
            continue
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if _is_review_plan_skill(block):
                return True
            if block.get("type") == "text" and SLASH_COMMAND_MARKER in str(block.get("text", "")):
                return True
    return False


def deny(reason: str) -> None:
    decision = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(decision))


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        transcript = Path(str(payload.get("transcript_path") or ""))
        with transcript.open(encoding="utf-8") as lines:
            reviewed = review_plan_invoked(lines)
    except (OSError, ValueError, AttributeError) as exc:
        deny(f"require_plan_review could not read the transcript ({exc}); blocking (fail closed).")
        return 0
    if not reviewed:
        deny(
            "Run /review-plan before exiting plan mode (AGENTS.md §4). Invoke the Skill tool with "
            "skill 'review-plan', fold P0/P1 findings into the plan, then call ExitPlanMode again."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

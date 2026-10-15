"""Tests for require_plan_review.py. Run: python -m unittest discover -s .claude/hooks -p "test_*.py"."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import require_plan_review as rpr  # noqa: E402

HOOK = Path(rpr.__file__)


def assistant_tool_use(name: str, tool_input: dict[str, object]) -> str:
    block = {"type": "tool_use", "name": name, "input": tool_input}
    return json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [block]}})


def user_text(text: str) -> str:
    return json.dumps({"type": "user", "message": {"role": "user", "content": text}})


class ReviewPlanInvokedTest(unittest.TestCase):
    def test_skill_tool_call_counts(self) -> None:
        lines = [assistant_tool_use("Skill", {"skill": "review-plan"})]
        self.assertTrue(rpr.review_plan_invoked(lines))

    def test_namespaced_skill_counts(self) -> None:
        lines = [assistant_tool_use("Skill", {"skill": "team:review-plan"})]
        self.assertTrue(rpr.review_plan_invoked(lines))

    def test_typed_slash_command_counts(self) -> None:
        lines = [user_text("<command-name>/review-plan</command-name>")]
        self.assertTrue(rpr.review_plan_invoked(lines))

    def test_mere_mention_does_not_count(self) -> None:
        lines = [user_text("we should run review-plan and write a Plan Review later")]
        self.assertFalse(rpr.review_plan_invoked(lines))

    def test_other_skill_does_not_count(self) -> None:
        lines = [assistant_tool_use("Skill", {"skill": "writing-plans"})]
        self.assertFalse(rpr.review_plan_invoked(lines))

    def test_corrupt_lines_are_skipped(self) -> None:
        lines = ["{not json", assistant_tool_use("Skill", {"skill": "review-plan"})]
        self.assertTrue(rpr.review_plan_invoked(lines))


class MainEntryPointTest(unittest.TestCase):
    def run_hook(self, payload: dict[str, object]) -> dict[str, object] | None:
        result = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=dict(os.environ),
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def test_blocks_when_not_reviewed(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write(user_text("hello") + "\n")
        try:
            out = self.run_hook({"transcript_path": f.name})
        finally:
            os.unlink(f.name)
        assert out is not None
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")  # type: ignore[index]

    def test_allows_when_reviewed(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write(assistant_tool_use("Skill", {"skill": "review-plan"}) + "\n")
        try:
            self.assertIsNone(self.run_hook({"transcript_path": f.name}))
        finally:
            os.unlink(f.name)

    def test_unreadable_transcript_fails_closed(self) -> None:
        out = self.run_hook({"transcript_path": "does/not/exist.jsonl"})
        assert out is not None
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()

"""Tests for protect_paths.py. Run: python -m unittest discover -s .claude/hooks -p "test_*.py"."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protect_paths as pp  # noqa: E402

HOOK = Path(pp.__file__)
REPO_ROOT = HOOK.parent.parent.parent

CONFIG = """# comment lines and blanks are ignored

eval/corpus/**
eval/corpus.lock
eval/thresholds.yaml
.claude/hooks/**
"""


class ProtectPathsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        self.config = self.project / "protected-paths.txt"
        self.config.write_text(CONFIG, encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def decide(self, tool: str, **tool_input: object) -> str | None:
        return pp.decide(tool, dict(tool_input), self.project, self.config)

    # File tools
    def test_edit_of_corpus_file_is_blocked(self) -> None:
        self.assertIsNotNone(self.decide("Edit", file_path="eval/corpus/attack.jsonl"))

    def test_write_with_absolute_path_is_blocked(self) -> None:
        target = self.project / "eval" / "thresholds.yaml"
        self.assertIsNotNone(self.decide("Write", file_path=str(target)))

    def test_backslash_and_mixed_case_path_is_blocked(self) -> None:
        self.assertIsNotNone(self.decide("Edit", file_path="Eval\\Corpus\\benign.jsonl"))

    def test_traversal_into_protected_path_is_blocked(self) -> None:
        self.assertIsNotNone(self.decide("Edit", file_path="firewall/../eval/corpus.lock"))

    def test_nested_file_under_protected_dir_is_blocked(self) -> None:
        self.assertIsNotNone(self.decide("Write", file_path=".claude/hooks/sub/x.py"))

    def test_notebook_edit_uses_notebook_path(self) -> None:
        self.assertIsNotNone(self.decide("NotebookEdit", notebook_path="eval/corpus/x.ipynb"))

    def test_edit_of_source_file_is_allowed(self) -> None:
        self.assertIsNone(self.decide("Edit", file_path="firewall/engine.py"))

    def test_lookalike_sibling_is_allowed(self) -> None:
        self.assertIsNone(self.decide("Edit", file_path="eval/run_eval.py"))

    def test_path_outside_repo_is_allowed(self) -> None:
        outside = self.project.parent / "elsewhere" / "eval" / "corpus" / "a.jsonl"
        self.assertIsNone(self.decide("Write", file_path=str(outside)))

    def test_missing_file_path_fails_closed(self) -> None:
        self.assertIsNotNone(self.decide("Edit"))

    def test_unrelated_tool_is_ignored(self) -> None:
        self.assertIsNone(self.decide("Read", file_path="eval/corpus/attack.jsonl"))

    # Shell tools
    def test_read_only_shell_command_is_allowed(self) -> None:
        self.assertIsNone(self.decide("Bash", command="cat eval/corpus/attack.jsonl"))

    def test_stream_merge_redirect_is_not_a_write(self) -> None:
        self.assertIsNone(self.decide("Bash", command="grep id eval/corpus/a.jsonl 2>&1"))

    def test_append_redirect_is_blocked(self) -> None:
        self.assertIsNotNone(self.decide("Bash", command='echo "{}" >> eval/corpus/attack.jsonl'))

    def test_sed_in_place_is_blocked(self) -> None:
        self.assertIsNotNone(self.decide("Bash", command="sed -i s/1.0/0.5/ eval/thresholds.yaml"))

    def test_write_in_later_segment_is_blocked(self) -> None:
        cmd = "python -m pytest -q && rm eval/corpus.lock"
        self.assertIsNotNone(self.decide("Bash", command=cmd))

    def test_cd_into_protected_dir_is_blocked(self) -> None:
        self.assertIsNotNone(self.decide("Bash", command="cd eval/corpus && rm attack.jsonl"))

    def test_powershell_set_content_is_blocked(self) -> None:
        cmd = "Set-Content -Path eval\\corpus\\attack.jsonl -Value x"
        self.assertIsNotNone(self.decide("PowerShell", command=cmd))

    def test_rtk_prefixed_read_is_allowed(self) -> None:
        self.assertIsNone(self.decide("Bash", command="rtk git diff eval/corpus/attack.jsonl"))

    def test_shell_command_not_naming_protected_path_is_allowed(self) -> None:
        self.assertIsNone(self.decide("Bash", command="python scripts/verify.py"))

    def test_missing_command_fails_closed(self) -> None:
        self.assertIsNotNone(self.decide("Bash"))

    # Config
    def test_missing_config_raises_so_main_fails_closed(self) -> None:
        self.config.unlink()
        with self.assertRaises(OSError):
            self.decide("Edit", file_path="firewall/engine.py")

    def test_empty_config_raises(self) -> None:
        self.config.write_text("# nothing\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.decide("Edit", file_path="firewall/engine.py")


class MainEntryPointTest(unittest.TestCase):
    """Runs the hook as Claude Code does: JSON on stdin, decision on stdout, exit code."""

    def run_hook(self, stdin: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HOOK)],
            input=stdin,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**os.environ, "CLAUDE_PROJECT_DIR": str(REPO_ROOT)},
            timeout=30,
        )

    def test_protected_edit_emits_deny_decision(self) -> None:
        payload = {"tool_name": "Edit", "tool_input": {"file_path": "eval/corpus/attack.jsonl"}}
        result = self.run_hook(json.dumps(payload))
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")

    def test_unprotected_edit_emits_nothing(self) -> None:
        payload = {"tool_name": "Edit", "tool_input": {"file_path": "firewall/engine.py"}}
        result = self.run_hook(json.dumps(payload))
        self.assertEqual((result.returncode, result.stdout.strip()), (0, ""))

    def test_malformed_input_exits_2_to_block(self) -> None:
        result = self.run_hook("not json")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()

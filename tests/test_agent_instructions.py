"""Guard test: every tool-specific agent file must keep pointing at AGENTS.md (no rule drift)."""

from __future__ import annotations

from pathlib import Path

import pytest

POINTER_FILES = [
    "CLAUDE.md",
    "GEMINI.md",
    ".github/copilot-instructions.md",
    ".cursor/rules/agents.mdc",
    ".windsurf/rules/agents.md",
    ".clinerules/agents.md",
    ".aider.conf.yml",
    ".gemini/settings.json",
]


@pytest.mark.parametrize("relative_path", POINTER_FILES)
def test_every_agent_pointer_file_references_agents_md(
    repo_root: Path, relative_path: str
) -> None:
    text = (repo_root / relative_path).read_text(encoding="utf-8")

    assert "AGENTS.md" in text


def test_claude_md_imports_agents_md(repo_root: Path) -> None:
    lines = (repo_root / "CLAUDE.md").read_text(encoding="utf-8").splitlines()

    assert "@AGENTS.md" in lines

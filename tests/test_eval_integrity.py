"""The human-owned corpus is intact, well-formed and covers every rule (PLAN.md W0b)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import BaseModel, ConfigDict

from firewall.models import RULE_REASONS, EvalRequest, Reason, Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "eval" / "corpus"


class Expected(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Verdict
    reasons: list[Reason]


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    description: str
    request: EvalRequest
    expected: Expected


def load_pin_module() -> Any:
    spec = importlib.util.spec_from_file_location("pin_corpus", REPO_ROOT / "scripts/pin_corpus.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def rows(name: str) -> list[dict[str, Any]]:
    lines = (CORPUS / name).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


@pytest.mark.parametrize("name", ["attack.jsonl", "benign.jsonl"])
def test_every_corpus_row_parses_as_eval_case(name: str) -> None:
    cases = [EvalCase.model_validate(row) for row in rows(name)]

    assert cases
    assert len({case.id for case in cases}) == len(cases)


def test_corpus_hashes_match_lock() -> None:
    pin = load_pin_module()
    locked = json.loads((REPO_ROOT / "eval" / "corpus.lock").read_text(encoding="utf-8"))

    assert locked == pin.current_hashes()


def test_attack_corpus_exercises_every_reason_code() -> None:
    covered = {reason for row in rows("attack.jsonl") for reason in row["expected"]["reasons"]}

    assert {r.value for r in RULE_REASONS} <= covered


def test_attack_rows_never_expect_allow_and_benign_rows_never_expect_deny() -> None:
    assert all(r["expected"]["decision"] != "ALLOW" for r in rows("attack.jsonl"))
    assert all(r["expected"]["decision"] != "DENY" for r in rows("benign.jsonl"))


def test_thresholds_define_every_gate() -> None:
    thresholds = yaml.safe_load((REPO_ROOT / "eval" / "thresholds.yaml").read_text("utf-8"))

    assert set(thresholds) == {
        "attack_block_rate_min",
        "benign_false_deny_rate_max",
        "expectation_match_rate_min",
    }

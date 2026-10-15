"""Mutation check on the real corpus: every rule must carry weight (AGENTS.md §5, PLAN.md W3)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from firewall.engine import evaluate
from firewall.policy import load_policy
from firewall.rules import DEFAULT_RULES

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_run_eval() -> Any:
    spec = importlib.util.spec_from_file_location("run_eval", REPO_ROOT / "eval" / "run_eval.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_mutation_disabling_any_rule_lets_an_attack_through() -> None:
    run_eval = load_run_eval()
    attacks = run_eval.load_cases(REPO_ROOT / "eval" / "corpus" / "attack.jsonl")
    policy = load_policy(REPO_ROOT / "policy" / "policy.yaml")

    survivors = run_eval.mutation_survivors(DEFAULT_RULES, attacks, policy, evaluate)

    assert survivors == []

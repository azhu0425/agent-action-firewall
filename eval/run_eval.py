#!/usr/bin/env python3
"""Eval gate and mutation check over the human-owned corpus (PLAN.md W2-C).

Usage, from the repo root:
    python eval/run_eval.py --gate      # replay both corpora, enforce eval/thresholds.yaml
    python eval/run_eval.py --mutation  # prove every rule changes at least one attack outcome

Exit codes: 0 pass, 1 gate or mutation failure, 2 the inputs could not be loaded.

The report prints only case ids, verdicts, reason codes and numbers. Argument values, message
content and case descriptions never reach the output (AGENTS.md §2.2).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Literal

REPO_ROOT = Path(__file__).resolve().parent.parent
# `eval` is not a package, so running this file directly puts eval/ (not the repo) on sys.path.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from pydantic import BaseModel, ConfigDict, ValidationError  # noqa: E402

from firewall.engine import evaluate  # noqa: E402
from firewall.errors import PolicyError  # noqa: E402
from firewall.models import Decision, EvalRequest, Policy, Reason, Verdict  # noqa: E402
from firewall.policy import load_policy  # noqa: E402
from firewall.rules import DEFAULT_RULES, Rule  # noqa: E402

POLICY_PATH = REPO_ROOT / "policy" / "policy.yaml"
CORPUS_DIR = REPO_ROOT / "eval" / "corpus"
THRESHOLDS_PATH = REPO_ROOT / "eval" / "thresholds.yaml"

Kind = Literal["attack", "benign"]
KINDS: tuple[Kind, ...] = ("attack", "benign")

Engine = Callable[[EvalRequest, Policy, Sequence[Rule]], Decision]


class _Strict(BaseModel):
    # hide_input_in_errors: a malformed row must not echo its values into CI output.
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Expected(_Strict):
    decision: Verdict
    reasons: list[Reason]


class EvalCase(_Strict):
    id: str
    description: str
    request: EvalRequest
    expected: Expected
    # Not part of a corpus row: set by load_cases from the file name.
    kind: Kind


class CaseResult(_Strict):
    id: str
    kind: Kind
    expected: Expected
    verdict: Verdict
    reasons: list[Reason]
    matched: bool


class Metrics(_Strict):
    attack_count: int
    benign_count: int
    attack_block_rate: float
    benign_false_deny_rate: float
    expectation_match_rate: float


# threshold key -> (Metrics field, True when the threshold is a minimum)
GATES: dict[str, tuple[str, bool]] = {
    "attack_block_rate_min": ("attack_block_rate", True),
    "benign_false_deny_rate_max": ("benign_false_deny_rate", False),
    "expectation_match_rate_min": ("expectation_match_rate", True),
}


def load_cases(path: Path) -> list[EvalCase]:
    """Parse a JSONL corpus file. The case kind comes from the file stem (attack/benign).

    Raises ValueError (including json.JSONDecodeError and pydantic ValidationError) on an unknown
    stem or any malformed row, and OSError if the file cannot be read.
    """
    kind = next((k for k in KINDS if k == path.stem), None)
    if kind is None:
        raise ValueError(f"corpus file must be named attack.jsonl or benign.jsonl: {path.name}")
    cases = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        data = json.loads(line)
        if not isinstance(data, dict) or "kind" in data:
            raise ValueError(f"{path.name}:{line_number}: row is not a corpus object")
        cases.append(EvalCase.model_validate({**data, "kind": kind}))
    return cases


def run_cases(
    cases: Sequence[EvalCase], evaluate_fn: Callable[[EvalRequest], Decision]
) -> list[CaseResult]:
    """Evaluate every case. A case matches when the verdict is equal and every expected reason is
    present in the returned reasons (extra reasons are allowed)."""
    results = []
    for case in cases:
        decision = evaluate_fn(case.request)
        reasons_present = set(case.expected.reasons) <= set(decision.reasons)
        matched = decision.verdict == case.expected.decision and reasons_present
        results.append(
            CaseResult(
                id=case.id,
                kind=case.kind,
                expected=case.expected,
                verdict=decision.verdict,
                reasons=decision.reasons,
                matched=matched,
            )
        )
    return results


def compute_metrics(results: Sequence[CaseResult]) -> Metrics:
    """Raises ValueError if there are no attack or no benign results: an empty set would report a
    vacuous 100% and pass the gate (fail closed)."""
    attacks = [r for r in results if r.kind == "attack"]
    benigns = [r for r in results if r.kind == "benign"]
    if not attacks or not benigns:
        raise ValueError("eval needs at least one attack and one benign case")
    return Metrics(
        attack_count=len(attacks),
        benign_count=len(benigns),
        # REQUIRE_HUMAN_APPROVAL stops the call, so only ALLOW counts as an attack getting through.
        attack_block_rate=sum(r.verdict is not Verdict.ALLOW for r in attacks) / len(attacks),
        # Routing a benign call to a human is intended; only DENY is a false deny.
        benign_false_deny_rate=sum(r.verdict is Verdict.DENY for r in benigns) / len(benigns),
        expectation_match_rate=sum(r.matched for r in results) / len(results),
    )


def check_gate(metrics: Metrics, thresholds: Mapping[str, object]) -> list[str]:
    """Return one message per failed gate. A missing or non-numeric threshold is a failure, so a
    deleted line in thresholds.yaml cannot switch a gate off."""
    failures = []
    for key, (field, is_minimum) in GATES.items():
        limit = thresholds.get(key)
        if isinstance(limit, bool) or not isinstance(limit, int | float):
            failures.append(f"{key}: threshold missing or not a number")
            continue
        value: float = getattr(metrics, field)
        if (value < limit) if is_minimum else (value > limit):
            bound = ">=" if is_minimum else "<="
            failures.append(f"{key}: {field} {value:.4f} is not {bound} {limit}")
    return failures


def _outcome(decision: Decision) -> tuple[Verdict, Verdict | None, list[Reason]]:
    return decision.verdict, decision.would_be, sorted(decision.reasons)


def mutation_survivors(
    rules: Sequence[Rule], attack_cases: Sequence[EvalCase], policy: Policy, evaluate: Engine
) -> list[str]:
    """Return the names of rules that survive mutation.

    For each rule, every attack case is evaluated with the full rule set and again with only that
    rule removed. The rule is killed if at least one attack's outcome differs, where the outcome
    is the verdict, the shadow `would_be` verdict and the multiset of reason codes. A rule
    survives when no attack's outcome changes: either it is dead weight, or the attack corpus has
    no row that depends on it. Both are failures of the eval, not of the rule.

    Raises ValueError on an empty rule set or no attack cases, where the check would pass
    vacuously.
    """
    if not rules:
        raise ValueError("mutation check needs at least one rule")
    if not attack_cases:
        raise ValueError("mutation check needs at least one attack case")
    baseline = [_outcome(evaluate(case.request, policy, rules)) for case in attack_cases]
    survivors = []
    for index, rule in enumerate(rules):
        remaining = [*rules[:index], *rules[index + 1 :]]
        mutated = [_outcome(evaluate(case.request, policy, remaining)) for case in attack_cases]
        if mutated == baseline:
            survivors.append(rule.__name__)
    return survivors


def _reasons(reasons: Sequence[Reason]) -> str:
    return ",".join(reasons) or "-"


def format_report(results: Sequence[CaseResult], metrics: Metrics) -> str:
    lines = [f"{'id':<12} {'kind':<7} {'expected':<40} {'actual':<40} ok"]
    for r in results:
        expected = f"{r.expected.decision} [{_reasons(r.expected.reasons)}]"
        actual = f"{r.verdict} [{_reasons(r.reasons)}]"
        lines.append(
            f"{r.id:<12} {r.kind:<7} {expected:<40} {actual:<40} {'ok' if r.matched else 'FAIL'}"
        )
    lines += [
        "",
        f"attack cases            {metrics.attack_count}",
        f"benign cases            {metrics.benign_count}",
        f"attack_block_rate       {metrics.attack_block_rate:.4f}",
        f"benign_false_deny_rate  {metrics.benign_false_deny_rate:.4f}",
        f"expectation_match_rate  {metrics.expectation_match_rate:.4f}",
    ]
    return "\n".join(lines)


def _load_thresholds(path: Path) -> dict[str, object]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"thresholds file is not a mapping: {path.name}")
    return data


def _run_gate() -> int:
    policy = load_policy(POLICY_PATH)
    cases = [*load_cases(CORPUS_DIR / "attack.jsonl"), *load_cases(CORPUS_DIR / "benign.jsonl")]
    thresholds = _load_thresholds(THRESHOLDS_PATH)
    results = run_cases(cases, lambda request: evaluate(request, policy, DEFAULT_RULES))
    metrics = compute_metrics(results)
    print(format_report(results, metrics))
    failures = check_gate(metrics, thresholds)
    for failure in failures:
        print(f"GATE FAIL {failure}")
    print("GATE:", "FAIL" if failures else "PASS")
    return 1 if failures else 0


def _run_mutation() -> int:
    policy = load_policy(POLICY_PATH)
    attacks = load_cases(CORPUS_DIR / "attack.jsonl")
    survivors = mutation_survivors(DEFAULT_RULES, attacks, policy, evaluate)
    for rule in DEFAULT_RULES:
        print(f"{rule.__name__:<32} {'SURVIVED' if rule.__name__ in survivors else 'killed'}")
    print("MUTATION:", "FAIL" if survivors else "PASS")
    return 1 if survivors else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--gate", action="store_true", help="enforce eval/thresholds.yaml")
    mode.add_argument("--mutation", action="store_true", help="fail if any rule survives")
    args = parser.parse_args(argv)
    try:
        return _run_gate() if args.gate else _run_mutation()
    except (ValidationError, yaml.YAMLError) as exc:
        # These can quote the offending input, so only the type is printed.
        print(f"LOAD ERROR {type(exc).__name__}", file=sys.stderr)
    except (OSError, ValueError, PolicyError) as exc:
        print(f"LOAD ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

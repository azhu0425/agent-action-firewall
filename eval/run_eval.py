#!/usr/bin/env python3
"""Eval gate and mutation check over the human-owned corpus (PLAN.md W2-C).

Usage, from the repo root:
    python eval/run_eval.py --gate      # replay both corpora, enforce eval/thresholds.yaml
    python eval/run_eval.py --mutation  # prove every rule stops at least one attack

Exit codes: 0 pass, 1 gate or mutation failure, 2 the inputs could not be loaded or evaluation
raised.

The report prints only case ids, verdicts, reason codes and numbers. Argument values, message
content and case descriptions never reach the output (AGENTS.md §2.2).
"""

from __future__ import annotations

import argparse
import json
import math
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
from firewall.models import (  # noqa: E402
    VERDICT_SEVERITY,
    Decision,
    EvalRequest,
    Policy,
    Reason,
    Verdict,
)
from firewall.policy import _UniqueKeyLoader, load_policy  # noqa: E402
from firewall.rules import DEFAULT_RULES, Rule  # noqa: E402

POLICY_PATH = REPO_ROOT / "policy" / "policy.yaml"
CORPUS_DIR = REPO_ROOT / "eval" / "corpus"
THRESHOLDS_PATH = REPO_ROOT / "eval" / "thresholds.yaml"

Kind = Literal["attack", "benign"]
KINDS: tuple[Kind, ...] = ("attack", "benign")
Mode = Literal["gate", "mutation"]

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


def _require_unique_ids(cases: Sequence[EvalCase]) -> None:
    seen: set[str] = set()
    for case in cases:
        if case.id in seen:
            raise ValueError(f"duplicate case id: {case.id}")
        seen.add(case.id)


def load_cases(path: Path) -> list[EvalCase]:
    """Parse a JSONL corpus file. The case kind comes from the file stem (attack/benign).

    Raises ValueError (including json.JSONDecodeError and pydantic ValidationError) on an unknown
    stem, a duplicate id or any malformed row, and OSError if the file cannot be read.
    """
    kind = next((k for k in KINDS if k == path.stem), None)
    if kind is None:
        raise ValueError(f"corpus file must be named attack.jsonl or benign.jsonl: {path.name}")
    cases = []
    # utf-8-sig: an editor-added BOM must not turn into a parse failure.
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        data = json.loads(line)
        if not isinstance(data, dict) or "kind" in data:
            raise ValueError(f"{path.name}:{line_number}: row is not a corpus object")
        cases.append(EvalCase.model_validate({**data, "kind": kind}))
    _require_unique_ids(cases)
    return cases


def load_thresholds(path: Path) -> dict[str, object]:
    """Raises ValueError unless the file is a YAML mapping with unique keys. Values are checked
    by check_gate."""
    try:
        # Duplicate keys rejected: a later `..._min: 0.0` must not silently win in review.
        data = yaml.load(path.read_bytes(), Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader
    except yaml.YAMLError:
        data = None
    if not isinstance(data, dict):
        raise ValueError(f"thresholds file is not a YAML mapping with unique keys: {path.name}")
    return data


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
        # A shadow-mode ALLOW is not blocked either: the call passes whatever would_be says.
        attack_block_rate=sum(r.verdict is not Verdict.ALLOW for r in attacks) / len(attacks),
        # Routing a benign call to a human is intended; only DENY is a false deny.
        benign_false_deny_rate=sum(r.verdict is Verdict.DENY for r in benigns) / len(benigns),
        expectation_match_rate=sum(r.matched for r in results) / len(results),
    )


def check_gate(metrics: Metrics, thresholds: Mapping[str, object]) -> list[str]:
    """Return one message per failed gate. A threshold that is missing, not a real number (bools
    included), not finite or outside [0, 1] is itself a failure, so a bad edit to thresholds.yaml
    cannot switch a gate off."""
    failures = []
    for key, (field, is_minimum) in GATES.items():
        limit = thresholds.get(key)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int | float)
            or not math.isfinite(limit)
            or not 0 <= limit <= 1
        ):
            failures.append(f"{key}: threshold missing or not a number in [0, 1]")
            continue
        value: float = getattr(metrics, field)
        if (value < limit) if is_minimum else (value > limit):
            bound = ">=" if is_minimum else "<="
            failures.append(f"{key}: {field} {value:.4f} is not {bound} {limit}")
    return failures


def _enforced_severity(decision: Decision) -> int:
    # Shadow mode always returns ALLOW, so the verdict enforce mode would have given is compared.
    verdict = decision.would_be if decision.would_be is not None else decision.verdict
    return VERDICT_SEVERITY[verdict]


def mutation_survivors(
    rules: Sequence[Rule], attack_cases: Sequence[EvalCase], policy: Policy, evaluate: Engine
) -> list[str]:
    """Return the names of rules that survive mutation (AGENTS.md §5).

    For each rule, every attack case is evaluated with the full rule set and again with only that
    rule removed. The rule is killed if, for at least one attack, the mutated verdict is strictly
    less restrictive than the baseline verdict (by VERDICT_SEVERITY; in shadow mode the would_be
    verdicts are compared). That is, disabling the rule lets an attack further through. A rule
    survives otherwise, including when removing it changes only the reason codes: either the rule
    is dead weight or the attack corpus has no row that depends on it.

    Raises ValueError on an empty rule set or no attack cases, where the check would pass
    vacuously.
    """
    if not rules:
        raise ValueError("mutation check needs at least one rule")
    if not attack_cases:
        raise ValueError("mutation check needs at least one attack case")
    baseline = [_enforced_severity(evaluate(case.request, policy, rules)) for case in attack_cases]
    survivors = []
    for index, rule in enumerate(rules):
        remaining = [*rules[:index], *rules[index + 1 :]]
        mutated = [
            _enforced_severity(evaluate(case.request, policy, remaining)) for case in attack_cases
        ]
        if not any(after < before for before, after in zip(baseline, mutated, strict=True)):
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


def _gate(
    policy: Policy,
    cases: Sequence[EvalCase],
    thresholds: Mapping[str, object],
    engine: Engine,
    rules: Sequence[Rule],
) -> int:
    results = run_cases(cases, lambda request: engine(request, policy, rules))
    metrics = compute_metrics(results)
    print(format_report(results, metrics))
    failures = check_gate(metrics, thresholds)
    for failure in failures:
        print(f"GATE FAIL {failure}")
    print("GATE:", "FAIL" if failures else "PASS")
    return 1 if failures else 0


def _mutation(
    policy: Policy, attacks: Sequence[EvalCase], engine: Engine, rules: Sequence[Rule]
) -> int:
    survivors = mutation_survivors(rules, attacks, policy, engine)
    for rule in rules:
        print(f"{rule.__name__:<32} {'SURVIVED' if rule.__name__ in survivors else 'killed'}")
    print("MUTATION:", "FAIL" if survivors else "PASS")
    return 1 if survivors else 0


def run(
    mode: Mode,
    *,
    policy_path: Path = POLICY_PATH,
    corpus_dir: Path = CORPUS_DIR,
    thresholds_path: Path = THRESHOLDS_PATH,
    engine: Engine = evaluate,
    rules: Sequence[Rule] = DEFAULT_RULES,
) -> int:
    """Run the gate or the mutation check and return the process exit code (0, 1 or 2)."""
    try:
        policy = load_policy(policy_path)
        attacks = load_cases(corpus_dir / "attack.jsonl")
        if mode == "gate":
            cases = [*attacks, *load_cases(corpus_dir / "benign.jsonl")]
            _require_unique_ids(cases)
            thresholds = load_thresholds(thresholds_path)
        elif not rules:
            raise ValueError("mutation check needs at least one rule; DEFAULT_RULES is empty")
    except ValidationError as exc:
        # Pydantic errors can name the offending keys, so only the type is printed.
        print(f"LOAD ERROR {type(exc).__name__}", file=sys.stderr)
        return 2
    except (OSError, ValueError, PolicyError) as exc:
        print(f"LOAD ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    try:
        if mode == "gate":
            return _gate(policy, cases, thresholds, engine, rules)
        return _mutation(policy, attacks, engine, rules)
    # Any evaluation error fails the run. Its message may carry request data, so only the type
    # is printed.
    except Exception as exc:
        print(f"EVAL ERROR {type(exc).__name__}", file=sys.stderr)
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--gate", action="store_true", help="enforce eval/thresholds.yaml")
    mode.add_argument("--mutation", action="store_true", help="fail if any rule survives")
    args = parser.parse_args(argv)
    return run("gate" if args.gate else "mutation")


if __name__ == "__main__":
    sys.exit(main())

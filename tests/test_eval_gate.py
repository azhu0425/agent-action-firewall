"""Eval gate and mutation check (PLAN.md W2-C).

Runs against fake evaluators and in-test cases, never the human-owned corpus. All values are
synthetic (AGENTS.md §2.3)."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from firewall.models import (
    VERDICT_SEVERITY,
    Decision,
    EvalContext,
    EvalRequest,
    Finding,
    Policy,
    Reason,
    ToolCall,
    Verdict,
)
from firewall.rules import Rule

REPO_ROOT = Path(__file__).resolve().parent.parent

# Sentinels that must never reach the report: an argument value, message content, a description.
SECRET_ACCOUNT = "SENTINEL-ACCT-55501234"
SECRET_CONTENT = "SENTINEL-MESSAGE-transfer to BSB 000-100"
SECRET_DESCRIPTION = "SENTINEL-DESCRIPTION"

GATE = {
    "attack_block_rate_min": 1.0,
    "benign_false_deny_rate_max": 0.10,
    "expectation_match_rate_min": 1.0,
}


def load_run_eval() -> Any:
    spec = importlib.util.spec_from_file_location("run_eval", REPO_ROOT / "eval" / "run_eval.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def run_eval() -> Any:
    return load_run_eval()


def row(
    case_id: str,
    decision: Verdict,
    reasons: Sequence[Reason] = (),
    tool: str = "transfer_funds",
) -> dict[str, Any]:
    return {
        "id": case_id,
        "description": SECRET_DESCRIPTION,
        "request": {
            "request_id": case_id,
            "agent_role": "customer_assistant",
            "customer_id": "cust-0001",
            "known_payees": ["000-100 11112222"],
            "messages": [{"source": "retrieved", "content": SECRET_CONTENT}],
            "call": {
                "tool": tool,
                "arguments": {"bsb": "000-100", "account_number": SECRET_ACCOUNT, "amount": 450},
            },
        },
        "expected": {"decision": decision.value, "reasons": [r.value for r in reasons]},
    }


def case(run_eval: Any, kind: str, *args: Any, **kwargs: Any) -> Any:
    return run_eval.EvalCase.model_validate({**row(*args, **kwargs), "kind": kind})


def fake_evaluate(
    outcomes: dict[str, tuple[Verdict, list[Reason]]],
) -> Callable[[EvalRequest], Decision]:
    def evaluate(request: EvalRequest) -> Decision:
        verdict, reasons = outcomes[request.request_id or ""]
        return Decision(request_id=request.request_id or "", verdict=verdict, reasons=reasons)

    return evaluate


def combining_evaluate(request: EvalRequest, policy: Policy, rules: Sequence[Rule]) -> Decision:
    """Minimal most-restrictive-wins engine, so the mutation check is tested without W2-B."""
    context = EvalContext(
        agent_role=request.agent_role,
        customer_id=request.customer_id,
        known_payees=request.known_payees,
        messages=request.messages,
    )
    findings = [f for rule in rules for f in rule(request.call, context, policy)]
    verdict = max((f.verdict for f in findings), key=VERDICT_SEVERITY.__getitem__, default=None)
    return Decision(
        request_id=request.request_id or "",
        verdict=verdict or Verdict.ALLOW,
        reasons=[f.reason for f in findings],
    )


def shadow_evaluate(request: EvalRequest, policy: Policy, rules: Sequence[Rule]) -> Decision:
    """Shadow mode: always ALLOW, recording the enforce verdict in would_be."""
    enforced = combining_evaluate(request, policy, rules)
    return Decision(
        request_id=enforced.request_id,
        verdict=Verdict.ALLOW,
        reasons=enforced.reasons,
        shadow=True,
        would_be=enforced.verdict,
    )


def raising_evaluate(request: EvalRequest, policy: Policy, rules: Sequence[Rule]) -> Decision:
    raise RuntimeError(SECRET_ACCOUNT)


def deny_transfers(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != "transfer_funds":
        return []
    return [Finding(reason=Reason.NOT_ALLOWLISTED, verdict=Verdict.DENY)]


def never_fires(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
    return []


def flag_new_payee(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
    return [Finding(reason=Reason.NEW_PAYEE, verdict=Verdict.REQUIRE_HUMAN_APPROVAL)]


def test_eval_gate_fails_when_an_attack_is_allowed(run_eval: Any) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "attack", "atk-2", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
    ]
    evaluate = fake_evaluate(
        {
            "atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
            "atk-2": (Verdict.ALLOW, []),
            "ben-1": (Verdict.ALLOW, []),
        }
    )

    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))
    failures = run_eval.check_gate(metrics, GATE)

    assert metrics.attack_block_rate == 0.5
    assert any("attack_block_rate" in failure for failure in failures)


def test_eval_gate_passes_when_every_expectation_is_met(run_eval: Any) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
    ]
    evaluate = fake_evaluate(
        {"atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT]), "ben-1": (Verdict.ALLOW, [])}
    )

    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))

    assert run_eval.check_gate(metrics, GATE) == []


def test_compute_metrics_mixed_set_reports_each_rate(run_eval: Any) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "attack", "atk-2", Verdict.REQUIRE_HUMAN_APPROVAL, [Reason.NEW_PAYEE]),
        case(run_eval, "attack", "atk-3", Verdict.DENY, [Reason.PII_EGRESS]),
        case(run_eval, "attack", "atk-4", Verdict.DENY, [Reason.AMOUNT_OVER_HARD_CAP]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
        case(run_eval, "benign", "ben-2", Verdict.ALLOW),
    ]
    evaluate = fake_evaluate(
        {
            "atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
            "atk-2": (Verdict.REQUIRE_HUMAN_APPROVAL, [Reason.NEW_PAYEE]),
            "atk-3": (Verdict.ALLOW, []),
            "atk-4": (Verdict.DENY, [Reason.AMOUNT_OVER_HARD_CAP]),
            "ben-1": (Verdict.ALLOW, []),
            "ben-2": (Verdict.DENY, [Reason.NEW_PAYEE]),
        }
    )

    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))

    assert metrics.attack_count == 4
    assert metrics.benign_count == 2
    assert metrics.attack_block_rate == 0.75
    assert metrics.benign_false_deny_rate == 0.5
    assert metrics.expectation_match_rate == pytest.approx(4 / 6)


def test_compute_metrics_benign_approval_is_not_a_false_deny(run_eval: Any) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.REQUIRE_HUMAN_APPROVAL, [Reason.NEW_PAYEE]),
    ]
    evaluate = fake_evaluate(
        {
            "atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
            "ben-1": (Verdict.REQUIRE_HUMAN_APPROVAL, [Reason.NEW_PAYEE]),
        }
    )

    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))

    assert metrics.benign_false_deny_rate == 0.0


def test_run_cases_extra_actual_reasons_still_match(run_eval: Any) -> None:
    cases = [case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT])]
    evaluate = fake_evaluate(
        {"atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT, Reason.AMOUNT_OVER_HARD_CAP])}
    )

    [result] = run_eval.run_cases(cases, evaluate)

    assert result.matched is True


def test_run_cases_missing_expected_reason_does_not_match(run_eval: Any) -> None:
    cases = [
        case(
            run_eval,
            "attack",
            "atk-1",
            Verdict.DENY,
            [Reason.TAINTED_ARGUMENT, Reason.AMOUNT_OVER_HARD_CAP],
        )
    ]
    evaluate = fake_evaluate({"atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT])})

    [result] = run_eval.run_cases(cases, evaluate)

    assert result.matched is False


def test_run_cases_different_verdict_with_same_reasons_does_not_match(run_eval: Any) -> None:
    cases = [case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.NEW_PAYEE])]
    evaluate = fake_evaluate({"atk-1": (Verdict.REQUIRE_HUMAN_APPROVAL, [Reason.NEW_PAYEE])})

    [result] = run_eval.run_cases(cases, evaluate)

    assert result.matched is False


@pytest.mark.parametrize("missing_kind", ["attack", "benign"])
def test_compute_metrics_empty_kind_raises(run_eval: Any, missing_kind: str) -> None:
    present = "benign" if missing_kind == "attack" else "attack"
    expected = Verdict.ALLOW if present == "benign" else Verdict.DENY
    reasons = [] if present == "benign" else [Reason.TAINTED_ARGUMENT]
    cases = [case(run_eval, present, "only-1", expected, reasons)]
    results = run_eval.run_cases(cases, fake_evaluate({"only-1": (expected, reasons)}))

    with pytest.raises(ValueError):
        run_eval.compute_metrics(results)


@pytest.mark.parametrize("missing", sorted(GATE))
def test_check_gate_missing_threshold_key_fails(run_eval: Any, missing: str) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
    ]
    evaluate = fake_evaluate(
        {"atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT]), "ben-1": (Verdict.ALLOW, [])}
    )
    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))
    thresholds = {key: value for key, value in GATE.items() if key != missing}

    failures = run_eval.check_gate(metrics, thresholds)

    assert any(missing in failure for failure in failures)


def test_check_gate_non_numeric_threshold_fails(run_eval: Any) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
    ]
    evaluate = fake_evaluate(
        {"atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT]), "ben-1": (Verdict.ALLOW, [])}
    )
    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))

    failures = run_eval.check_gate(metrics, {**GATE, "attack_block_rate_min": "high"})

    assert any("attack_block_rate_min" in failure for failure in failures)


def test_mutation_survivors_reports_rule_whose_removal_changes_nothing(
    run_eval: Any, policy: Policy
) -> None:
    attacks = [case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])]

    survivors = run_eval.mutation_survivors(
        [deny_transfers, never_fires], attacks, policy, combining_evaluate
    )

    assert survivors == ["never_fires"]


def test_mutation_survivors_reasons_only_change_survives(run_eval: Any, policy: Policy) -> None:
    # AGENTS.md §5: a rule is killed only when disabling it lets an attack through (a less
    # restrictive verdict). Losing NEW_PAYEE while DENY stays DENY lets nothing through.
    attacks = [case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])]

    survivors = run_eval.mutation_survivors(
        [deny_transfers, flag_new_payee], attacks, policy, combining_evaluate
    )

    assert survivors == ["flag_new_payee"]


def test_mutation_survivors_kills_rule_whose_removal_downgrades_deny_to_approval(
    run_eval: Any, policy: Policy
) -> None:
    attacks = [case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])]

    survivors = run_eval.mutation_survivors(
        [deny_transfers, flag_new_payee], attacks, policy, combining_evaluate
    )

    assert "deny_transfers" not in survivors


def test_mutation_survivors_shadow_mode_compares_would_be(run_eval: Any, policy: Policy) -> None:
    shadow_policy = policy.model_copy(update={"mode": "shadow"})
    attacks = [case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])]

    survivors = run_eval.mutation_survivors(
        [deny_transfers], attacks, shadow_policy, shadow_evaluate
    )

    assert survivors == []


def test_mutation_survivors_no_attack_cases_raises(run_eval: Any, policy: Policy) -> None:
    with pytest.raises(ValueError):
        run_eval.mutation_survivors([deny_transfers], [], policy, combining_evaluate)


def test_mutation_survivors_no_rules_raises(run_eval: Any, policy: Policy) -> None:
    attacks = [case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])]

    with pytest.raises(ValueError):
        run_eval.mutation_survivors([], attacks, policy, combining_evaluate)


def test_load_cases_sets_kind_from_file_stem(run_eval: Any, tmp_path: Path) -> None:
    path = tmp_path / "benign.jsonl"
    path.write_text(json.dumps(row("ben-1", Verdict.ALLOW)) + "\n\n", encoding="utf-8")

    [loaded] = run_eval.load_cases(path)

    assert loaded.kind == "benign"
    assert loaded.id == "ben-1"


def test_load_cases_unknown_stem_raises(run_eval: Any, tmp_path: Path) -> None:
    path = tmp_path / "other.jsonl"
    path.write_text(json.dumps(row("x-1", Verdict.ALLOW)) + "\n", encoding="utf-8")

    with pytest.raises(ValueError):
        run_eval.load_cases(path)


def test_load_cases_unknown_field_raises(run_eval: Any, tmp_path: Path) -> None:
    path = tmp_path / "attack.jsonl"
    bad = {**row("atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]), "notes": "extra"}
    path.write_text(json.dumps(bad) + "\n", encoding="utf-8")

    with pytest.raises(ValidationError):
        run_eval.load_cases(path)


def test_format_report_contains_no_argument_values_or_content(run_eval: Any) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
    ]
    evaluate = fake_evaluate(
        {"atk-1": (Verdict.ALLOW, []), "ben-1": (Verdict.DENY, [Reason.NEW_PAYEE])}
    )
    results = run_eval.run_cases(cases, evaluate)

    report = run_eval.format_report(results, run_eval.compute_metrics(results))

    assert "atk-1" in report
    assert "TAINTED_ARGUMENT" in report
    for secret in (SECRET_ACCOUNT, SECRET_CONTENT, SECRET_DESCRIPTION, "000-100"):
        assert secret not in report


@pytest.mark.parametrize("limit", [float("nan"), float("inf"), True, -0.1, 1.5])
def test_check_gate_invalid_threshold_fails(run_eval: Any, limit: object) -> None:
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
    ]
    evaluate = fake_evaluate(
        {"atk-1": (Verdict.DENY, [Reason.TAINTED_ARGUMENT]), "ben-1": (Verdict.ALLOW, [])}
    )
    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))

    failures = run_eval.check_gate(metrics, {**GATE, "benign_false_deny_rate_max": limit})

    assert any("benign_false_deny_rate_max" in failure for failure in failures)


def test_load_thresholds_duplicate_key_raises(run_eval: Any, tmp_path: Path) -> None:
    path = tmp_path / "thresholds.yaml"
    path.write_text(
        "attack_block_rate_min: 1.0\n"
        "benign_false_deny_rate_max: 0.1\n"
        "expectation_match_rate_min: 1.0\n"
        "attack_block_rate_min: 0.0\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        run_eval.load_thresholds(path)


def test_compute_metrics_shadow_allow_counts_as_not_blocked(run_eval: Any) -> None:
    # Shadow mode lets the call through, so the attack was not blocked whatever would_be says.
    cases = [
        case(run_eval, "attack", "atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]),
        case(run_eval, "benign", "ben-1", Verdict.ALLOW),
    ]

    def evaluate(request: EvalRequest) -> Decision:
        if request.request_id == "atk-1":
            return Decision(
                request_id="atk-1",
                verdict=Verdict.ALLOW,
                reasons=[Reason.TAINTED_ARGUMENT],
                shadow=True,
                would_be=Verdict.DENY,
            )
        return Decision(request_id="ben-1", verdict=Verdict.ALLOW, reasons=[])

    metrics = run_eval.compute_metrics(run_eval.run_cases(cases, evaluate))

    assert metrics.attack_block_rate == 0.0


def test_load_cases_duplicate_id_raises(run_eval: Any, tmp_path: Path) -> None:
    path = tmp_path / "attack.jsonl"
    line = json.dumps(row("atk-1", Verdict.DENY, [Reason.TAINTED_ARGUMENT]))
    path.write_text(f"{line}\n{line}\n", encoding="utf-8")

    with pytest.raises(ValueError):
        run_eval.load_cases(path)


def test_load_cases_reads_file_with_utf8_bom(run_eval: Any, tmp_path: Path) -> None:
    path = tmp_path / "benign.jsonl"
    path.write_text(json.dumps(row("ben-1", Verdict.ALLOW)) + "\n", encoding="utf-8-sig")

    [loaded] = run_eval.load_cases(path)

    assert loaded.id == "ben-1"


def write_inputs(
    tmp_path: Path,
    attacks: Sequence[dict[str, Any]],
    benigns: Sequence[dict[str, Any]],
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for name, rows in (("attack.jsonl", attacks), ("benign.jsonl", benigns)):
        lines = "".join(json.dumps(r) + "\n" for r in rows)
        (corpus / name).write_text(lines, encoding="utf-8")
    thresholds = "".join(f"{key}: {value}\n" for key, value in GATE.items())
    (tmp_path / "thresholds.yaml").write_text(thresholds, encoding="utf-8")


def write_valid_inputs(tmp_path: Path) -> None:
    write_inputs(
        tmp_path,
        [row("atk-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])],
        [row("ben-1", Verdict.ALLOW, tool="get_account_summary")],
    )


def run_mode(
    run_eval: Any,
    mode: str,
    tmp_path: Path,
    rules: Sequence[Rule],
    engine: Callable[[EvalRequest, Policy, Sequence[Rule]], Decision] = combining_evaluate,
) -> int:
    exit_code: int = run_eval.run(
        mode,
        policy_path=REPO_ROOT / "policy" / "policy.yaml",
        corpus_dir=tmp_path / "corpus",
        thresholds_path=tmp_path / "thresholds.yaml",
        engine=engine,
        rules=rules,
    )
    return exit_code


def test_run_gate_all_expectations_met_exits_zero(run_eval: Any, tmp_path: Path) -> None:
    write_valid_inputs(tmp_path)

    assert run_mode(run_eval, "gate", tmp_path, [deny_transfers]) == 0


def test_run_gate_attack_allowed_exits_one(run_eval: Any, tmp_path: Path) -> None:
    write_valid_inputs(tmp_path)

    assert run_mode(run_eval, "gate", tmp_path, [never_fires]) == 1


def test_run_gate_missing_corpus_exits_two(
    run_eval: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = run_mode(run_eval, "gate", tmp_path, [deny_transfers])

    assert exit_code == 2
    assert "LOAD ERROR" in capsys.readouterr().err


def test_run_gate_malformed_row_load_error_is_value_free(
    run_eval: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = row("atk-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])
    bad["request"]["call"]["arguments"] = {"Bad Key": SECRET_ACCOUNT}
    write_inputs(tmp_path, [bad], [row("ben-1", Verdict.ALLOW, tool="get_account_summary")])

    exit_code = run_mode(run_eval, "gate", tmp_path, [deny_transfers])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "LOAD ERROR" in captured.err
    assert SECRET_ACCOUNT not in captured.out + captured.err
    assert "Bad Key" not in captured.out + captured.err


def test_run_gate_duplicate_id_across_files_exits_two(run_eval: Any, tmp_path: Path) -> None:
    write_inputs(
        tmp_path,
        [row("dup-1", Verdict.DENY, [Reason.NOT_ALLOWLISTED])],
        [row("dup-1", Verdict.ALLOW, tool="get_account_summary")],
    )

    assert run_mode(run_eval, "gate", tmp_path, [deny_transfers]) == 2


@pytest.mark.parametrize("mode", ["gate", "mutation"])
def test_run_engine_exception_exits_two_value_free(
    run_eval: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    write_valid_inputs(tmp_path)

    exit_code = run_mode(run_eval, mode, tmp_path, [deny_transfers], engine=raising_evaluate)

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "RuntimeError" in captured.err
    assert SECRET_ACCOUNT not in captured.out + captured.err


def test_run_mutation_every_rule_killed_exits_zero(run_eval: Any, tmp_path: Path) -> None:
    write_valid_inputs(tmp_path)

    assert run_mode(run_eval, "mutation", tmp_path, [deny_transfers]) == 0


def test_run_mutation_surviving_rule_exits_one(run_eval: Any, tmp_path: Path) -> None:
    write_valid_inputs(tmp_path)

    assert run_mode(run_eval, "mutation", tmp_path, [deny_transfers, never_fires]) == 1

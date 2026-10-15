"""Engine tests (PLAN.md W2-B). Only fake rules, injected through the `rules` parameter."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from firewall.engine import evaluate
from firewall.models import (
    EvalContext,
    EvalRequest,
    Finding,
    Policy,
    Reason,
    ToolCall,
    Verdict,
)

SECRET_MARKER = "SECRET-000100-99887766"


def make_request(**overrides: object) -> EvalRequest:
    fields: dict[str, object] = {
        "agent_role": "customer_assistant",
        "customer_id": "cust-001",
        "known_payees": [],
        "messages": [{"source": "user", "content": "What is my balance?"}],
        "call": {"tool": "get_account_summary", "arguments": {}},
    }
    fields.update(overrides)
    return EvalRequest.model_validate(fields)


def finding_rule(*findings: Finding) -> Any:
    def rule(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
        return list(findings)

    return rule


def no_findings(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
    return []


def raising_rule(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
    raise ValueError(SECRET_MARKER)


def garbage_rule(call: ToolCall, context: EvalContext, policy: Policy) -> Any:
    return "not a list"


def garbage_item_rule(call: ToolCall, context: EvalContext, policy: Policy) -> Any:
    return [{"reason": "NEW_PAYEE", "verdict": "ALLOW"}]


HUMAN = Finding(reason=Reason.NEW_PAYEE, verdict=Verdict.REQUIRE_HUMAN_APPROVAL, argument="bsb")
DENY_CAP = Finding(reason=Reason.AMOUNT_OVER_HARD_CAP, verdict=Verdict.DENY, argument="amount")
SOFT_CAP = Finding(
    reason=Reason.AMOUNT_OVER_SOFT_CAP, verdict=Verdict.REQUIRE_HUMAN_APPROVAL, argument="amount"
)


@pytest.fixture
def shadow_policy(policy: Policy) -> Policy:
    return policy.model_copy(update={"mode": "shadow"})


@pytest.mark.parametrize(
    "ordered", [(HUMAN, DENY_CAP), (DENY_CAP, HUMAN)], ids=["human-first", "deny-first"]
)
def test_evaluate_most_restrictive_decision_wins(
    policy: Policy, ordered: tuple[Finding, Finding]
) -> None:
    rules = [finding_rule(ordered[0]), finding_rule(ordered[1])]

    decision = evaluate(make_request(), policy, rules=rules)

    assert decision.verdict is Verdict.DENY


def test_evaluate_returns_every_fired_reason(policy: Policy) -> None:
    decision = evaluate(
        make_request(), policy, rules=[finding_rule(HUMAN), no_findings, finding_rule(DENY_CAP)]
    )

    assert decision.reasons == [Reason.NEW_PAYEE, Reason.AMOUNT_OVER_HARD_CAP]
    assert decision.findings == [HUMAN, DENY_CAP]


def test_evaluate_without_policy_denies_policy_unloaded() -> None:
    decision = evaluate(make_request(), None, rules=[no_findings])

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.POLICY_UNLOADED]


def test_evaluate_rule_exception_denies_evaluator_error(policy: Policy) -> None:
    decision = evaluate(make_request(), policy, rules=[no_findings, raising_rule])

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.EVALUATOR_ERROR]


def test_evaluate_no_findings_allows(policy: Policy) -> None:
    decision = evaluate(make_request(), policy, rules=[no_findings])

    assert decision.verdict is Verdict.ALLOW
    assert decision.reasons == []
    assert decision.shadow is False
    assert decision.would_be is None


def test_shadow_mode_allows_and_reports_would_be_decision(shadow_policy: Policy) -> None:
    decision = evaluate(make_request(), shadow_policy, rules=[finding_rule(DENY_CAP)])

    assert decision.verdict is Verdict.ALLOW
    assert decision.shadow is True
    assert decision.would_be is Verdict.DENY
    assert decision.reasons == [Reason.AMOUNT_OVER_HARD_CAP]


def test_evaluate_rule_exception_message_never_logged(
    policy: Policy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    evaluate(make_request(), policy, rules=[raising_rule])

    assert caplog.records
    assert SECRET_MARKER not in caplog.text
    assert all(SECRET_MARKER not in str(r.__dict__) for r in caplog.records)


STANDARD_RECORD_ATTRS = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}
# AGENTS.md §2.2: request id, tool name, decision, reason codes and latency only.
ALLOWED_EXTRA_ATTRS = frozenset({"request_id", "fields"})


def test_evaluate_rule_exception_log_carries_only_allowed_fields(
    policy: Policy, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="firewall.engine")

    evaluate(make_request(request_id="req-7"), policy, rules=[raising_rule])

    records = [r for r in caplog.records if r.name == "firewall.engine"]
    assert len(records) == 1
    record = records[0]
    assert set(record.__dict__) - STANDARD_RECORD_ATTRS <= ALLOWED_EXTRA_ATTRS
    assert record.__dict__.get("request_id") == "req-7"
    assert record.__dict__.get("fields") == {
        "tool": "get_account_summary",
        "verdict": "DENY",
        "reasons": ["EVALUATOR_ERROR"],
    }
    rendered = record.getMessage() + str(record.__dict__)
    assert "raising_rule" not in rendered
    assert "ValueError" not in rendered


def test_shadow_mode_rule_exception_still_denies(shadow_policy: Policy) -> None:
    decision = evaluate(make_request(), shadow_policy, rules=[raising_rule])

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.EVALUATOR_ERROR]


@pytest.mark.parametrize("rule", [garbage_rule, garbage_item_rule])
def test_evaluate_rule_returning_garbage_denies_evaluator_error(policy: Policy, rule: Any) -> None:
    decision = evaluate(make_request(), policy, rules=[rule])

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.EVALUATOR_ERROR]


def test_evaluate_duplicate_reasons_deduplicated(policy: Policy) -> None:
    decision = evaluate(
        make_request(), policy, rules=[finding_rule(SOFT_CAP, HUMAN), finding_rule(SOFT_CAP)]
    )

    assert decision.verdict is Verdict.REQUIRE_HUMAN_APPROVAL
    assert decision.reasons == [Reason.AMOUNT_OVER_SOFT_CAP, Reason.NEW_PAYEE]
    assert len(decision.findings) == 3


def test_evaluate_echoes_given_request_id(policy: Policy) -> None:
    decision = evaluate(make_request(request_id="req-42"), policy, rules=[no_findings])

    assert decision.request_id == "req-42"


def test_evaluate_empty_rule_set_denies_no_rules(policy: Policy) -> None:
    decision = evaluate(make_request(), policy, rules=[])

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.NO_RULES]


def test_shadow_mode_no_findings_reports_would_be_allow(shadow_policy: Policy) -> None:
    decision = evaluate(make_request(), shadow_policy, rules=[no_findings])

    assert decision.verdict is Verdict.ALLOW
    assert decision.shadow is True
    assert decision.would_be is Verdict.ALLOW
    assert decision.reasons == []


def test_evaluate_fired_rule_then_exception_drops_partial_findings(policy: Policy) -> None:
    decision = evaluate(make_request(), policy, rules=[finding_rule(HUMAN), raising_rule])

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.EVALUATOR_ERROR]
    assert decision.findings == []


@pytest.mark.parametrize("reason", [Reason.NOT_ALLOWLISTED, Reason.INVALID_ARGUMENT])
def test_shadow_mode_fail_closed_rule_reason_still_denies(
    shadow_policy: Policy, reason: Reason
) -> None:
    fail_closed = Finding(reason=reason, verdict=Verdict.DENY)

    decision = evaluate(
        make_request(), shadow_policy, rules=[finding_rule(SOFT_CAP), finding_rule(fail_closed)]
    )

    assert decision.verdict is Verdict.DENY
    assert reason in decision.reasons


@pytest.mark.parametrize(
    "bad",
    [
        Finding(reason=Reason.EVALUATOR_ERROR, verdict=Verdict.DENY),
        Finding(reason=Reason.POLICY_UNLOADED, verdict=Verdict.DENY),
        Finding(reason=Reason.NEW_PAYEE, verdict=Verdict.ALLOW),
    ],
    ids=["engine-reason-evaluator", "engine-reason-unloaded", "allow-verdict"],
)
def test_evaluate_finding_breaking_rule_contract_denies_evaluator_error(
    policy: Policy, bad: Finding
) -> None:
    decision = evaluate(make_request(), policy, rules=[finding_rule(bad)])

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.EVALUATOR_ERROR]


def test_evaluate_rule_mutation_not_visible_to_next_rule(policy: Policy) -> None:
    seen: list[int] = []

    def mutating_rule(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
        context.messages.append(context.messages[0])
        policy.roles.clear()
        return []

    def observing_rule(call: ToolCall, context: EvalContext, policy: Policy) -> list[Finding]:
        seen.append(len(context.messages))
        seen.append(len(policy.roles))
        return []

    evaluate(make_request(), policy, rules=[mutating_rule, observing_rule])

    assert seen == [1, 2]


def test_evaluate_stamps_policy_sha256(policy: Policy) -> None:
    stamped = policy.model_copy(update={"sha256": "ab" * 32})

    decision = evaluate(make_request(), stamped, rules=[no_findings])

    assert decision.policy_sha256 == "ab" * 32

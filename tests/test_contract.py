"""The frozen W0a contract. These tests are permanent: replacing a stub never deletes one.

Changing anything asserted here needs a `contract:` PR (PLAN.md, "Rules for parallel work").
"""

from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from typing import Any

import pytest
from pydantic import ValidationError

from firewall import audit, engine, policy, rules, taint
from firewall.models import (
    Decision,
    EvalRequest,
    Message,
    Policy,
    Reason,
    Source,
    ToolCall,
    Verdict,
)

# (parameter name, annotation, default) per parameter, plus the return annotation. A default that
# is a module constant is pinned by identity below, not by repr, so filling it never breaks this.
EXPECTED_SIGNATURES: dict[Callable[..., Any], tuple[list[tuple[str, str, object]], str]] = {
    taint.normalise: ([("value", "str", inspect.Parameter.empty)], "str"),
    taint.tainted_arguments: (
        [
            ("call", "ToolCall", inspect.Parameter.empty),
            ("messages", "Sequence[Message]", inspect.Parameter.empty),
            ("fields", "frozenset[str]", inspect.Parameter.empty),
            ("min_length", "int", 6),
        ],
        "list[str]",
    ),
    policy.load_policy: ([("path", "Path", inspect.Parameter.empty)], "Policy"),
    engine.evaluate: (
        [
            ("request", "EvalRequest", inspect.Parameter.empty),
            ("policy", "Policy | None", inspect.Parameter.empty),
            ("rules", "Sequence[Rule]", rules.DEFAULT_RULES),
        ],
        "Decision",
    ),
    audit.append_audit: (
        [
            ("log", "Path", inspect.Parameter.empty),
            ("decision", "Decision", inspect.Parameter.empty),
            ("request", "EvalRequest", inspect.Parameter.empty),
            ("policy_sha256", "str", inspect.Parameter.empty),
        ],
        "None",
    ),
    audit.verify_chain: ([("log", "Path", inspect.Parameter.empty)], "int | None"),
}


def request(**overrides: object) -> EvalRequest:
    fields: dict[str, object] = {
        "agent_role": "customer_assistant",
        "customer_id": "cust-001",
        "known_payees": [],
        "messages": [{"source": "user", "content": "What is my balance?"}],
        "call": {"tool": "get_account_summary", "arguments": {}},
    }
    fields.update(overrides)
    return EvalRequest.model_validate(fields)


@pytest.mark.parametrize("function", list(EXPECTED_SIGNATURES), ids=lambda f: f.__qualname__)
def test_contract_signatures_match(function: Callable[..., Any]) -> None:
    expected_params, expected_return = EXPECTED_SIGNATURES[function]
    signature = inspect.signature(function)

    actual = [(p.name, p.annotation, p.default) for p in signature.parameters.values()]

    assert [(n, a) for n, a, _ in actual] == [(n, a) for n, a, _ in expected_params]
    for (name, _, default), (_, _, expected_default) in zip(actual, expected_params, strict=True):
        assert default is expected_default or default == expected_default, name
    assert signature.return_annotation == expected_return


def test_default_rules_is_a_rule_sequence() -> None:
    assert isinstance(rules.DEFAULT_RULES, Sequence)


def test_evaluate_with_empty_rule_set_denies(policy: Policy) -> None:
    decision = engine.evaluate(request(), policy, rules=())

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.NO_RULES]


def test_evaluate_without_policy_denies(policy: Policy) -> None:
    decision = engine.evaluate(request(), None, rules=())

    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.POLICY_UNLOADED]


def test_evaluate_assigns_unique_request_ids(policy: Policy) -> None:
    first = engine.evaluate(request(), policy, rules=())
    second = engine.evaluate(request(), policy, rules=())

    assert first.request_id != second.request_id


def test_eval_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        request(unexpected="x")


def test_message_source_is_restricted_enum() -> None:
    with pytest.raises(ValidationError):
        Message.model_validate({"source": "system", "content": "hi"})

    assert {s.value for s in Source} == {"user", "assistant", "tool_output", "retrieved"}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_tool_call_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(ValidationError):
        ToolCall.model_validate({"tool": "transfer_funds", "arguments": {"amount": value}})


@pytest.mark.parametrize("name", ["", "Transfer Funds", "transfer_funds\nINFO forged", "x" * 65])
def test_tool_and_argument_names_are_identifiers(name: str) -> None:
    with pytest.raises(ValidationError):
        ToolCall.model_validate({"tool": name, "arguments": {}})
    with pytest.raises(ValidationError):
        ToolCall.model_validate({"tool": "send_email", "arguments": {name: "x"}})


def test_message_content_is_bounded() -> None:
    with pytest.raises(ValidationError):
        Message.model_validate({"source": "user", "content": "x" * 20_001})


def test_policy_rejects_hard_cap_below_soft_cap() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {
                "version": "x",
                "roles": {"r": {"allowed_tools": [], "soft_cap_aud": 100, "hard_cap_aud": 50}},
                "high_risk_tools": ["transfer_funds"],
                "taint_fields": ["bsb"],
                "bank_email_domains": [],
            }
        )


@pytest.mark.parametrize("cap", [float("inf"), float("nan")])
def test_policy_rejects_non_finite_caps(cap: float) -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {
                "version": "x",
                "roles": {"r": {"allowed_tools": [], "soft_cap_aud": 0, "hard_cap_aud": cap}},
                "high_risk_tools": ["transfer_funds"],
                "taint_fields": ["bsb"],
                "bank_email_domains": [],
            }
        )


@pytest.mark.parametrize("field", ["high_risk_tools", "taint_fields"])
def test_policy_rejects_empty_taint_configuration(field: str) -> None:
    fields: dict[str, object] = {
        "version": "x",
        "roles": {},
        "high_risk_tools": ["transfer_funds"],
        "taint_fields": ["bsb"],
        "bank_email_domains": [],
    }
    fields[field] = []

    with pytest.raises(ValidationError):
        Policy.model_validate(fields)


@pytest.mark.parametrize(
    "fields",
    [
        {"verdict": "DENY", "reasons": []},
        {"verdict": "REQUIRE_HUMAN_APPROVAL", "reasons": []},
        {"verdict": "ALLOW", "reasons": [], "shadow": True},
        {"verdict": "ALLOW", "reasons": [], "would_be": "DENY"},
    ],
)
def test_decision_rejects_inconsistent_states(fields: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Decision.model_validate({"request_id": "r1", **fields})

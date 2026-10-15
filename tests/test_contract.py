"""The frozen W0a contract. These tests are permanent: replacing a stub never deletes one.

Changing anything asserted here needs a `contract:` PR (PLAN.md, "Rules for parallel work").
"""

from __future__ import annotations

import inspect
from collections.abc import Sequence

import pytest
from pydantic import ValidationError

from firewall import audit, engine, policy, rules, taint
from firewall.models import (
    Decision,
    EvalRequest,
    Message,
    Policy,
    Source,
    ToolCall,
    Verdict,
)

EXPECTED_SIGNATURES = {
    taint.normalise: "(value: 'str') -> 'str'",
    taint.tainted_arguments: (
        "(call: 'ToolCall', messages: 'Sequence[Message]', fields: 'frozenset[str]', "
        "min_length: 'int' = 6) -> 'list[str]'"
    ),
    policy.load_policy: "(path: 'Path') -> 'Policy'",
    engine.evaluate: (
        "(request: 'EvalRequest', policy: 'Policy | None', "
        "rules: 'Sequence[Rule]' = ()) -> 'Decision'"
    ),
    audit.append_audit: (
        "(log: 'Path', decision: 'Decision', request: 'EvalRequest', "
        "policy_sha256: 'str') -> 'None'"
    ),
    audit.verify_chain: "(log: 'Path') -> 'int | None'",
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
def test_contract_signatures_match(function: object) -> None:
    assert str(inspect.signature(function)) == EXPECTED_SIGNATURES[function]  # type: ignore[index, arg-type]


def test_default_rules_is_a_rule_sequence() -> None:
    assert isinstance(rules.DEFAULT_RULES, Sequence)


def test_evaluate_with_empty_rule_set_denies(policy: Policy) -> None:
    decision = engine.evaluate(request(), policy, rules=())

    assert isinstance(decision, Decision)
    assert decision.verdict is Verdict.DENY


def test_eval_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        request(unexpected="x")


def test_message_source_is_restricted_enum() -> None:
    with pytest.raises(ValidationError):
        Message.model_validate({"source": "system", "content": "hi"})

    assert {s.value for s in Source} == {"user", "assistant", "tool_output", "retrieved"}


def test_policy_rejects_hard_cap_below_soft_cap() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {
                "version": "x",
                "roles": {
                    "r": {"allowed_tools": [], "soft_cap_aud": 100, "hard_cap_aud": 50},
                },
                "high_risk_tools": [],
                "taint_fields": [],
                "bank_email_domains": [],
            }
        )


def test_tool_call_requires_tool_name() -> None:
    with pytest.raises(ValidationError):
        ToolCall.model_validate({"tool": "", "arguments": {}})

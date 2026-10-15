"""Fail-closed evaluation engine. Stub until stream W2-B replaces it."""

from __future__ import annotations

from collections.abc import Sequence

from firewall.models import Decision, EvalRequest, Policy, Reason, Verdict
from firewall.rules import DEFAULT_RULES, Rule


def evaluate(
    request: EvalRequest, policy: Policy | None, rules: Sequence[Rule] = DEFAULT_RULES
) -> Decision:
    # Fail closed: until the real engine exists, every call is denied.
    return Decision(
        request_id=request.request_id or "unassigned",
        verdict=Verdict.DENY,
        reasons=[Reason.EVALUATOR_ERROR],
    )

"""Fail-closed evaluation engine. Stub until stream W2-B replaces it."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from firewall.models import Decision, EvalRequest, Policy, Reason, Verdict
from firewall.rules import DEFAULT_RULES, Rule


def evaluate(
    request: EvalRequest, policy: Policy | None, rules: Sequence[Rule] = DEFAULT_RULES
) -> Decision:
    # Fail closed: until the real engine exists, every call is denied.
    if policy is None:
        reason = Reason.POLICY_UNLOADED
    elif not rules:
        reason = Reason.NO_RULES
    else:
        reason = Reason.EVALUATOR_ERROR
    return Decision(
        request_id=request.request_id or uuid.uuid4().hex,
        verdict=Verdict.DENY,
        reasons=[reason],
    )

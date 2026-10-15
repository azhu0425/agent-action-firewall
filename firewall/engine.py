"""Fail-closed evaluation engine: runs every rule and combines findings, most restrictive wins."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence

from firewall.models import (
    VERDICT_SEVERITY,
    Decision,
    EvalContext,
    EvalRequest,
    Finding,
    Policy,
    Reason,
    Verdict,
)
from firewall.rules import DEFAULT_RULES, Rule

logger = logging.getLogger(__name__)


class RuleContractError(TypeError):
    """A rule returned something other than a list of Finding objects."""


def _rule_name(rule: Rule) -> str:
    return getattr(rule, "__name__", type(rule).__name__)


def _deny(request_id: str, reason: Reason, policy: Policy | None) -> Decision:
    # Fail-closed outcomes are never shadowed: an error must not become ALLOW (AGENTS.md §2.1).
    return Decision(
        request_id=request_id,
        verdict=Verdict.DENY,
        reasons=[reason],
        policy_sha256=(policy.sha256 or None) if policy is not None else None,
    )


def _run_rule(
    rule: Rule, request: EvalRequest, context: EvalContext, policy: Policy
) -> list[Finding]:
    result = rule(request.call, context, policy)
    # Checked explicitly: Decision would coerce dicts into Findings and hide a broken rule.
    if not isinstance(result, list) or not all(isinstance(f, Finding) for f in result):
        raise RuleContractError
    return result


def evaluate(
    request: EvalRequest, policy: Policy | None, rules: Sequence[Rule] = DEFAULT_RULES
) -> Decision:
    """Evaluate one proposed tool call. Never raises for rule errors and never ALLOWs on one.

    No policy -> DENY POLICY_UNLOADED; no rules -> DENY NO_RULES; any rule raising or breaking
    its return contract -> DENY EVALUATOR_ERROR, in enforce and shadow mode alike.
    """
    request_id = request.request_id or uuid.uuid4().hex
    if policy is None:
        return _deny(request_id, Reason.POLICY_UNLOADED, policy)
    if not rules:
        return _deny(request_id, Reason.NO_RULES, policy)

    stage = "engine"
    try:
        context = EvalContext(
            agent_role=request.agent_role,
            customer_id=request.customer_id,
            known_payees=list(request.known_payees),
            messages=list(request.messages),
        )
        findings: list[Finding] = []
        for rule in rules:
            stage = _rule_name(rule)
            findings.extend(_run_rule(rule, request, context, policy))
        stage = "engine"
        verdict = max(
            (f.verdict for f in findings),
            key=VERDICT_SEVERITY.__getitem__,
            default=Verdict.ALLOW,
        )
        reasons = list(dict.fromkeys(f.reason for f in findings))
        sha = policy.sha256 or None
        if policy.mode == "shadow":
            return Decision(
                request_id=request_id,
                verdict=Verdict.ALLOW,
                reasons=reasons,
                findings=findings,
                shadow=True,
                would_be=verdict,
                policy_sha256=sha,
            )
        return Decision(
            request_id=request_id,
            verdict=verdict,
            reasons=reasons,
            findings=findings,
            policy_sha256=sha,
        )
    except Exception as exc:
        # Fail-closed boundary (AGENTS.md §6). Log the type only: messages may carry values (§2.2).
        logger.warning(
            "evaluator error",
            extra={"request_id": request_id, "rule": stage, "error_type": type(exc).__name__},
        )
        return _deny(request_id, Reason.EVALUATOR_ERROR, policy)

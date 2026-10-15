"""Policy rules: pure functions (call, context, policy) -> findings. Filled by stream W2-A."""

from __future__ import annotations

from collections.abc import Callable

from firewall.models import EvalContext, Finding, Policy, ToolCall

Rule = Callable[[ToolCall, EvalContext, Policy], list[Finding]]


def role_allowlist(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    return []


def invalid_arguments(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    return []


def amount_limits(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    return []


def new_payee(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    return []


def pii_egress(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    return []


def tainted_argument(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    return []


# Empty until W2-A lands; the engine denies on an empty rule set, so this is fail-closed.
DEFAULT_RULES: tuple[Rule, ...] = ()

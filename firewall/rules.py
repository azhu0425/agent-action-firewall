"""Policy rules: pure functions (call, context, policy) -> findings. Filled by stream W2-A."""

from __future__ import annotations

from collections.abc import Callable

from firewall.models import EvalContext, Finding, Policy, ToolCall

Rule = Callable[[ToolCall, EvalContext, Policy], list[Finding]]

# Empty until W2-A lands; the engine denies on an empty rule set, so this is fail-closed.
DEFAULT_RULES: tuple[Rule, ...] = ()

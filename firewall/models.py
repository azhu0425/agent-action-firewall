"""Frozen contract shared by every stream (PLAN.md W0a). Change only through a `contract:` PR."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

ArgumentValue = str | int | float | bool | None


class _Strict(BaseModel):
    # extra="forbid": an unknown field is a malformed request, and malformed means DENY.
    model_config = ConfigDict(extra="forbid", frozen=True)


class Source(StrEnum):
    """Where a message in the agent's context came from. Only `user` is trusted."""

    USER = "user"
    ASSISTANT = "assistant"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED = "retrieved"


class Verdict(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    DENY = "DENY"


# Most-restrictive-wins ordering used when combining findings.
VERDICT_SEVERITY: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.REQUIRE_HUMAN_APPROVAL: 1,
    Verdict.DENY: 2,
}


class Reason(StrEnum):
    NOT_ALLOWLISTED = "NOT_ALLOWLISTED"  # tool unknown, or not permitted for the agent's role
    AMOUNT_OVER_SOFT_CAP = "AMOUNT_OVER_SOFT_CAP"  # above the role's soft cap: needs a human
    AMOUNT_OVER_HARD_CAP = "AMOUNT_OVER_HARD_CAP"  # above the role's hard cap: denied
    NEW_PAYEE = "NEW_PAYEE"  # payee not among the customer's known payees: needs a human
    PII_EGRESS = "PII_EGRESS"  # account/BSB/card data in an email leaving the bank domain
    TAINTED_ARGUMENT = "TAINTED_ARGUMENT"  # high-risk argument sourced from untrusted content
    POLICY_UNLOADED = "POLICY_UNLOADED"  # no valid policy is loaded: everything is denied
    NO_RULES = "NO_RULES"  # an empty rule set would allow everything, so it denies instead
    EVALUATOR_ERROR = "EVALUATOR_ERROR"  # a rule or the engine raised: fail closed


# Reasons produced by policy rules (as opposed to the engine's fail-closed reasons).
RULE_REASONS: frozenset[Reason] = frozenset(
    {
        Reason.NOT_ALLOWLISTED,
        Reason.AMOUNT_OVER_SOFT_CAP,
        Reason.AMOUNT_OVER_HARD_CAP,
        Reason.NEW_PAYEE,
        Reason.PII_EGRESS,
        Reason.TAINTED_ARGUMENT,
    }
)


class Message(_Strict):
    source: Source
    content: str


class ToolCall(_Strict):
    tool: str = Field(min_length=1)
    arguments: dict[str, ArgumentValue] = Field(default_factory=dict)


class EvalRequest(_Strict):
    request_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    agent_role: str = Field(min_length=1)
    customer_id: str = Field(min_length=1)
    # Payees the customer has paid before, as "<bsb> <account_number>" in any spacing/dashes.
    known_payees: list[str] = Field(default_factory=list)
    messages: list[Message]
    call: ToolCall


class EvalContext(_Strict):
    """What a rule may see besides the call itself. Built by the engine from the request."""

    agent_role: str
    customer_id: str
    known_payees: list[str]
    messages: list[Message]


class Finding(_Strict):
    reason: Reason
    verdict: Verdict
    # Names the argument involved, never its value (AGENTS.md §2.2).
    argument: str | None = None


class Decision(_Strict):
    request_id: str
    verdict: Verdict
    reasons: list[Reason]
    findings: list[Finding] = Field(default_factory=list)
    # Shadow mode returns ALLOW but records what enforce mode would have done.
    shadow: bool = False
    would_be: Verdict | None = None
    policy_sha256: str | None = None


class RolePolicy(_Strict):
    allowed_tools: list[str]
    soft_cap_aud: float = Field(ge=0)  # above this: REQUIRE_HUMAN_APPROVAL
    hard_cap_aud: float = Field(ge=0)  # above this: DENY

    @model_validator(mode="after")
    def _hard_cap_not_below_soft_cap(self) -> Self:
        if self.hard_cap_aud < self.soft_cap_aud:
            raise ValueError("hard_cap_aud must be >= soft_cap_aud")
        return self


class Policy(_Strict):
    version: str = Field(min_length=1)
    mode: Literal["enforce", "shadow"] = "enforce"
    roles: dict[str, RolePolicy]
    high_risk_tools: list[str]
    taint_fields: list[str]
    bank_email_domains: list[str]
    min_taint_length: int = Field(default=6, ge=1)
    # Set by load_policy from the file bytes; stamped on every audit record.
    sha256: str = ""

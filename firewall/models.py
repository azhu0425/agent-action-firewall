"""Frozen contract shared by every stream (PLAN.md W0a). Change only through a `contract:` PR."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

ArgumentValue = str | int | float | bool | None
# Tool and argument names are chosen by the (untrusted) agent and end up in logs and findings, so
# they are restricted to plain identifiers: no spaces, newlines or room for smuggled values.
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$")]

MAX_CONTENT_CHARS = 20_000
MAX_MESSAGES = 200


class _Strict(BaseModel):
    # extra="forbid": an unknown field is a malformed request, and malformed means DENY.
    # allow_inf_nan=False: NaN compares False with everything, so it would slip past every cap.
    # hide_input_in_errors=True: a ValidationError must never carry the submitted value (§2.2).
    model_config = ConfigDict(
        extra="forbid", frozen=True, allow_inf_nan=False, hide_input_in_errors=True
    )


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
    INVALID_ARGUMENT = "INVALID_ARGUMENT"  # required argument missing or malformed (e.g. amount)
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
        Reason.INVALID_ARGUMENT,
    }
)


class Message(_Strict):
    source: Source
    content: str = Field(max_length=MAX_CONTENT_CHARS)


class ToolCall(_Strict):
    tool: Identifier
    arguments: dict[Identifier, ArgumentValue] = Field(default_factory=dict, max_length=32)


class EvalRequest(_Strict):
    request_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    # Trust boundary (decisions.md DR-1): agent_role, customer_id and known_payees are supplied
    # by the orchestrator that hosts the agent, never by model output. Only `call` and the
    # non-user messages are untrusted.
    agent_role: Identifier
    customer_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    # Payees the customer has paid before, as "<bsb> <account_number>" in any spacing/dashes.
    known_payees: list[Annotated[str, StringConstraints(max_length=64)]] = Field(
        default_factory=list, max_length=500
    )
    messages: list[Message] = Field(max_length=MAX_MESSAGES)
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

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.verdict is not Verdict.ALLOW and not self.reasons:
            raise ValueError("a non-ALLOW decision must carry at least one reason")
        if self.shadow != (self.would_be is not None):
            raise ValueError("would_be is set exactly when shadow is true")
        return self


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
    # Empty lists would silently switch taint tracking off, so at least one entry is required.
    high_risk_tools: list[str] = Field(min_length=1)
    taint_fields: list[str] = Field(min_length=1)
    bank_email_domains: list[str]
    min_taint_length: int = Field(default=6, ge=1)
    # Set by load_policy from the file bytes; stamped on every audit record.
    sha256: str = ""

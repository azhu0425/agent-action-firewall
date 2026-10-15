"""Policy rules: pure functions (call, context, policy) -> findings.

Each rule returns `[]` when it does not apply. Findings name the argument, never its value
(AGENTS.md §2.2).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from firewall.models import (
    ArgumentValue,
    EvalContext,
    Finding,
    Policy,
    Reason,
    ToolCall,
    Verdict,
)
from firewall.taint import normalise, tainted_arguments

Rule = Callable[[ToolCall, EvalContext, Policy], list[Finding]]

_TRANSFER = "transfer_funds"
_EMAIL = "send_email"
_PAYEE_FIELDS = ("bsb", "account_number")
_EMAIL_TEXT_FIELDS = ("subject", "body")

# Exactly one address: a list or display-name form cannot smuggle an external recipient.
_SINGLE_ADDRESS = re.compile(r"[^@\s,;<>]+@([^@\s,;<>]+)")
_PII_PATTERNS = (
    re.compile(r"(?<!\d)\d{3}-\d{3}(?!\d)"),  # BSB: 999-001
    re.compile(r"(?<!\d)\d{8,10}(?!\d)"),  # account number: 12345678
    re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)"),  # card: 4000 1234 5678 9011
)


def _valid_amount(value: ArgumentValue) -> float | None:
    # bool is an int subclass; True must not pass as an amount of 1.
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        return None
    return float(value)


def _present(value: ArgumentValue) -> bool:
    return value is not None and normalise(str(value)) != ""


def _is_known_payee(call: ToolCall, ctx: EvalContext) -> bool:
    bsb = call.arguments.get("bsb")
    account = call.arguments.get("account_number")
    if not (_present(bsb) and _present(account)):
        return False
    known = {normalise(payee) for payee in ctx.known_payees}
    return normalise(f"{bsb}{account}") in known


def role_allowlist(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    role = policy.roles.get(ctx.agent_role)
    if role is None or call.tool not in role.allowed_tools:
        return [Finding(reason=Reason.NOT_ALLOWLISTED, verdict=Verdict.DENY)]
    return []


def invalid_arguments(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != _TRANSFER:
        return []
    findings = []
    if _valid_amount(call.arguments.get("amount")) is None:
        findings.append(
            Finding(reason=Reason.INVALID_ARGUMENT, verdict=Verdict.DENY, argument="amount")
        )
    for name in _PAYEE_FIELDS:
        if not _present(call.arguments.get(name)):
            findings.append(
                Finding(reason=Reason.INVALID_ARGUMENT, verdict=Verdict.DENY, argument=name)
            )
    return findings


def amount_limits(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != _TRANSFER:
        return []
    amount = _valid_amount(call.arguments.get("amount"))
    role = policy.roles.get(ctx.agent_role)
    # An invalid amount or unknown role is already denied by the rules above.
    if amount is None or role is None:
        return []
    if amount > role.hard_cap_aud:
        return [
            Finding(reason=Reason.AMOUNT_OVER_HARD_CAP, verdict=Verdict.DENY, argument="amount")
        ]
    if amount > role.soft_cap_aud:
        return [
            Finding(
                reason=Reason.AMOUNT_OVER_SOFT_CAP,
                verdict=Verdict.REQUIRE_HUMAN_APPROVAL,
                argument="amount",
            )
        ]
    return []


def new_payee(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != _TRANSFER:
        return []
    if not all(_present(call.arguments.get(name)) for name in _PAYEE_FIELDS):
        return []
    if _is_known_payee(call, ctx):
        return []
    return [Finding(reason=Reason.NEW_PAYEE, verdict=Verdict.REQUIRE_HUMAN_APPROVAL)]


def _is_bank_recipient(to: ArgumentValue, policy: Policy) -> bool:
    # Exact domain match only: subdomains and lookalikes are external.
    if not isinstance(to, str):
        return False
    match = _SINGLE_ADDRESS.fullmatch(to.strip())
    if match is None:
        return False
    bank_domains = {domain.casefold() for domain in policy.bank_email_domains}
    return match.group(1).casefold() in bank_domains


def pii_egress(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != _EMAIL or _is_bank_recipient(call.arguments.get("to"), policy):
        return []
    findings = []
    for name in _EMAIL_TEXT_FIELDS:
        value = call.arguments.get(name)
        if value is None:
            continue
        text = str(value)
        if any(pattern.search(text) for pattern in _PII_PATTERNS):
            findings.append(Finding(reason=Reason.PII_EGRESS, verdict=Verdict.DENY, argument=name))
    return findings


def tainted_argument(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool not in policy.high_risk_tools:
        return []
    tainted = tainted_arguments(
        call, ctx.messages, frozenset(policy.taint_fields), policy.min_taint_length
    )
    # DR-5: a known payee looked up in tool output may be re-paid; a new payee still needs a human.
    if call.tool == _TRANSFER and _is_known_payee(call, ctx):
        tainted = [name for name in tainted if name not in _PAYEE_FIELDS]
    return [
        Finding(reason=Reason.TAINTED_ARGUMENT, verdict=Verdict.DENY, argument=name)
        for name in tainted
    ]


DEFAULT_RULES: tuple[Rule, ...] = (
    role_allowlist,
    invalid_arguments,
    amount_limits,
    new_payee,
    pii_egress,
    tainted_argument,
)

"""Policy rules: pure functions (call, context, policy) -> findings.

Each rule returns `[]` when it does not apply. Findings name the argument, never its value
(AGENTS.md §2.2).
"""

from __future__ import annotations

import re
import unicodedata
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

# Closed argument sets (evidence/design.md). Anything else on a known tool is smuggling room
# (`cc`, `bcc`, `payee_account`), so it is denied rather than ignored.
TOOL_ARGUMENTS: dict[str, frozenset[str]] = {
    "get_account_summary": frozenset(),
    "transfer_funds": frozenset({"bsb", "account_number", "amount", "payee_name", "reference"}),
    "send_email": frozenset({"to", "subject", "body"}),
    "update_contact_details": frozenset({"email", "phone"}),
}

# Exactly one bare address: a list or display-name form could carry an external recipient.
_SINGLE_ADDRESS = re.compile(r"[^@\s,;<>\"]+@([^@\s,;<>\"]+)")
_DIGITS = re.compile(r"[0-9]+")
_BSB_DIGITS = 6
_ACCOUNT_DIGITS = range(6, 11)
# Six or more digits joined only by separators: BSB (000-910), account, card. Shorter runs are
# reference numbers and are allowed.
_PII_RUN = re.compile(r"\d{6,}")


def _finding(reason: Reason, verdict: Verdict, argument: str | None = None) -> Finding:
    return Finding(reason=reason, verdict=verdict, argument=argument)


def _valid_amount(value: ArgumentValue) -> float | None:
    # bool is an int subclass; True must not pass as an amount of 1.
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        amount = float(value)
    except OverflowError:
        return None
    return amount if amount > 0 else None


def _digit_field(value: ArgumentValue, lengths: range) -> str | None:
    """Normalised digits of a BSB/account given as str or int, or None when malformed."""
    # float is rejected: 12345678.0 is not an account number, and bool is not a number here.
    if isinstance(value, bool) or not isinstance(value, str | int):
        return None
    digits = normalise(str(value))
    if _DIGITS.fullmatch(digits) is None or len(digits) not in lengths:
        return None
    return digits


def _bsb(value: ArgumentValue) -> str | None:
    return _digit_field(value, range(_BSB_DIGITS, _BSB_DIGITS + 1))


def _account(value: ArgumentValue) -> str | None:
    return _digit_field(value, _ACCOUNT_DIGITS)


def _known_payee_pairs(known_payees: list[str]) -> set[tuple[str, str]]:
    # Compare (bsb, account) tuples, not concatenations, so the split cannot be moved.
    pairs = set()
    for payee in known_payees:
        digits = normalise(payee)
        if _DIGITS.fullmatch(digits) is None:
            continue
        bsb, account = digits[:_BSB_DIGITS], digits[_BSB_DIGITS:]
        if len(account) in _ACCOUNT_DIGITS:
            pairs.add((bsb, account))
    return pairs


def _is_known_payee(call: ToolCall, ctx: EvalContext) -> bool:
    bsb = _bsb(call.arguments.get("bsb"))
    account = _account(call.arguments.get("account_number"))
    if bsb is None or account is None:
        return False
    return (bsb, account) in _known_payee_pairs(ctx.known_payees)


def _single_address_domain(value: ArgumentValue) -> str | None:
    if not isinstance(value, str):
        return None
    match = _SINGLE_ADDRESS.fullmatch(value)
    return None if match is None else match.group(1).casefold()


def role_allowlist(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    role = policy.roles.get(ctx.agent_role)
    if role is None or call.tool not in role.allowed_tools:
        return [_finding(Reason.NOT_ALLOWLISTED, Verdict.DENY)]
    return []


def invalid_arguments(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    allowed = TOOL_ARGUMENTS.get(call.tool)
    # Unknown tools are denied by role_allowlist.
    if allowed is None:
        return []
    invalid = [name for name in call.arguments if name not in allowed]
    if call.tool == _TRANSFER:
        if _valid_amount(call.arguments.get("amount")) is None:
            invalid.append("amount")
        if _bsb(call.arguments.get("bsb")) is None:
            invalid.append("bsb")
        if _account(call.arguments.get("account_number")) is None:
            invalid.append("account_number")
    elif call.tool == _EMAIL and _single_address_domain(call.arguments.get("to")) is None:
        invalid.append("to")
    return [_finding(Reason.INVALID_ARGUMENT, Verdict.DENY, name) for name in invalid]


def amount_limits(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != _TRANSFER:
        return []
    amount = _valid_amount(call.arguments.get("amount"))
    role = policy.roles.get(ctx.agent_role)
    # An invalid amount or unknown role is already denied by the rules above.
    if amount is None or role is None:
        return []
    if amount > role.hard_cap_aud:
        return [_finding(Reason.AMOUNT_OVER_HARD_CAP, Verdict.DENY, "amount")]
    if amount > role.soft_cap_aud:
        return [_finding(Reason.AMOUNT_OVER_SOFT_CAP, Verdict.REQUIRE_HUMAN_APPROVAL, "amount")]
    return []


def new_payee(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != _TRANSFER:
        return []
    if any(call.arguments.get(name) is None for name in _PAYEE_FIELDS):
        return []
    if _is_known_payee(call, ctx):
        return []
    return [_finding(Reason.NEW_PAYEE, Verdict.REQUIRE_HUMAN_APPROVAL)]


def _contains_account_data(text: str) -> bool:
    # NFKC folds fullwidth digits; dropping every non-alphanumeric joins "1234.5678",
    # "1234_5678" and zero-width-space splits into one digit run.
    folded = unicodedata.normalize("NFKC", text)
    return _PII_RUN.search("".join(c for c in folded if c.isalnum())) is not None


def pii_egress(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool != _EMAIL:
        return []
    # Exact domain match only: subdomains, lookalikes and malformed recipients are external.
    domain = _single_address_domain(call.arguments.get("to"))
    if domain is not None and domain in {d.casefold() for d in policy.bank_email_domains}:
        return []
    return [
        _finding(Reason.PII_EGRESS, Verdict.DENY, name)
        for name in _EMAIL_TEXT_FIELDS
        if (value := call.arguments.get(name)) is not None and _contains_account_data(str(value))
    ]


def tainted_argument(call: ToolCall, ctx: EvalContext, policy: Policy) -> list[Finding]:
    if call.tool not in policy.high_risk_tools:
        return []
    tainted = tainted_arguments(
        call, ctx.messages, frozenset(policy.taint_fields), policy.min_taint_length
    )
    # DR-5: a known payee looked up in tool output may be re-paid; a new payee still needs a human.
    if call.tool == _TRANSFER and _is_known_payee(call, ctx):
        tainted = [name for name in tainted if name not in _PAYEE_FIELDS]
    return [_finding(Reason.TAINTED_ARGUMENT, Verdict.DENY, name) for name in tainted]


DEFAULT_RULES: tuple[Rule, ...] = (
    role_allowlist,
    invalid_arguments,
    amount_limits,
    new_payee,
    pii_egress,
    tainted_argument,
)

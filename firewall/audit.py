"""Hash-chained, append-only JSONL audit log.

Each record carries `prev_hash` (the previous record's `hash`, or GENESIS for the first) and its own
`hash` over the canonical JSON of every other field, so editing, deleting, reordering or
reformatting a record breaks the chain at that point.

Limitations (detectable only with an anchor held outside the file):
- Truncating the tail, or emptying the file, leaves a chain that still verifies. Callers must
  record `chain_head` (record count and last hash) somewhere the log's writer cannot alter, and
  compare it on verification.
- A full rewrite with recomputed hashes also verifies; the same external anchor catches it.

Records never hold argument values, message content or customer_id (AGENTS.md §2.2). Arguments are
represented by `args_sha256`, so a disputed call can be proven against the log without storing it.
A plain sha256 over low-entropy arguments (a BSB, an account number, an amount) can be
brute-forced back to the values; the production fix is an HMAC keyed from outside the log.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from firewall import __version__
from firewall.errors import AuditError
from firewall.models import Decision, EvalRequest

GENESIS = "0" * 64


def _canonical(value: object) -> str:
    # ensure_ascii: U+2028/U+0085 and friends are escaped, so only "\n" ever ends a record.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _read_lines(log: Path) -> list[str]:
    """Split on "\\n" only (str.splitlines would also break on U+2028, U+0085, ...)."""
    try:
        text = log.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditError("audit log could not be read") from exc
    if not text:
        return []
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines


def _sealed(line: str) -> tuple[str, object] | None:
    """Return (hash, prev_hash) if `line` is a canonical record whose hash matches, else None."""
    try:
        record = json.loads(line)
    except (ValueError, RecursionError):
        return None
    # The stored bytes must be exactly the canonical form: catches duplicate keys and reformatting
    # that a parse-then-rehash check would silently accept.
    if not isinstance(record, dict) or _canonical(record) != line:
        return None
    claimed = record.pop("hash", None)
    if not isinstance(claimed, str) or claimed != _sha256(record):
        return None
    return claimed, record.get("prev_hash")


def _check(line: str, expected_prev: str) -> str | None:
    """Return the record's hash if `line` is a valid link after `expected_prev`, else None."""
    sealed = _sealed(line)
    if sealed is None or sealed[1] != expected_prev:
        return None
    return sealed[0]


def _last_hash(log: Path) -> str:
    if not log.exists():
        return GENESIS
    lines = _read_lines(log)
    if not lines:
        return GENESIS
    sealed = _sealed(lines[-1])
    if sealed is None:
        # Chaining onto a corrupt or edited tail would launder the damage, so refuse to append.
        raise AuditError("audit log tail fails its hash check")
    return sealed[0]


def append_audit(log: Path, decision: Decision, request: EvalRequest, policy_sha256: str) -> None:
    """Append one chained record for `decision`. Raises AuditError on any IO failure.

    The policy hash comes from `decision.policy_sha256` when set; an empty `policy_sha256`
    argument defers to it, and two different non-empty values raise AuditError.
    Not safe for concurrent writers: read-last-hash then append is not atomic across processes.
    """
    if decision.policy_sha256 and policy_sha256 and decision.policy_sha256 != policy_sha256:
        raise AuditError("policy hash on the decision does not match the policy hash given")
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AuditError("audit log directory could not be created") from exc
    record: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "request_id": decision.request_id,
        "verdict": decision.verdict.value,
        "reasons": [reason.value for reason in decision.reasons],
        "shadow": decision.shadow,
        "would_be": decision.would_be.value if decision.would_be is not None else None,
        "tool": request.call.tool,
        "agent_role": request.agent_role,
        "args_sha256": _sha256(request.call.arguments),
        "policy_sha256": decision.policy_sha256 or policy_sha256,
        "engine_version": __version__,
        "prev_hash": _last_hash(log),
    }
    record["hash"] = _sha256(record)
    try:
        with log.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical(record) + "\n")
    except OSError as exc:
        raise AuditError("audit log could not be written") from exc


def verify_chain(log: Path) -> int | None:
    """Return the 0-based index of the first bad record, or None if the chain is intact.

    A record is bad if it is unparseable, not in canonical form, its hash does not match its
    content, or its prev_hash does not match the previous record's hash. A truncated tail is not
    detectable here: compare `chain_head` against an external anchor. Raises AuditError if the log
    cannot be read.
    """
    expected_prev = GENESIS
    for index, line in enumerate(_read_lines(log)):
        current = _check(line, expected_prev)
        if current is None:
            return index
        expected_prev = current
    return None


def chain_head(log: Path) -> tuple[int, str]:
    """Return (record count, last hash), or (0, GENESIS) for an empty log, for external anchoring.

    Raises AuditError if the log cannot be read or the chain is broken.
    """
    lines = _read_lines(log)
    head = GENESIS
    for index, line in enumerate(lines):
        current = _check(line, head)
        if current is None:
            raise AuditError(f"audit chain is broken at record {index}")
        head = current
    return len(lines), head


def read_records(log: Path) -> list[dict[str, object]]:
    """Parse every record for display, oldest first; a missing log is an empty one.

    Records are value-free by construction (argument values are stored only as args_sha256), so
    they are safe to return to a caller. Unparseable lines are skipped here: verify_chain is the
    integrity check, this is only a reader. Raises AuditError if the log exists but is unreadable.
    """
    if not log.exists():
        return []
    records: list[dict[str, object]] = []
    for line in _read_lines(log):
        try:
            parsed = json.loads(line)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records

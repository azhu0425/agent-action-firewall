"""Hash-chained, append-only JSONL audit log.

Each record carries `prev_hash` (the previous record's `hash`, or GENESIS for the first) and its own
`hash` over the canonical JSON of every other field, so editing, deleting or reordering a record
breaks the chain at that point. A full rewrite with recomputed hashes is only detectable by
comparing the head hash against a copy anchored outside the file.

Records never hold argument values, message content or customer_id (AGENTS.md §2.2). Arguments are
represented by `args_sha256`, so a disputed call can be proven against the log without storing it.
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


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _last_hash(log: Path) -> str:
    try:
        lines = log.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return GENESIS
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditError("audit log could not be read") from exc
    if not lines:
        return GENESIS
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        # Chaining onto a corrupt tail would launder the damage, so refuse to append.
        raise AuditError("audit log tail is unparseable") from exc
    if not isinstance(last, dict) or not isinstance(last.get("hash"), str):
        raise AuditError("audit log tail has no hash")
    return str(last["hash"])


def append_audit(log: Path, decision: Decision, request: EvalRequest, policy_sha256: str) -> None:
    """Append one chained record for `decision`. Raises AuditError on any IO failure.

    Not safe for concurrent writers: read-last-hash then append is not atomic across processes.
    """
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
        "policy_sha256": policy_sha256,
        "engine_version": __version__,
        "prev_hash": _last_hash(log),
    }
    record["hash"] = _sha256(record)
    try:
        with log.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(_canonical(record).decode("utf-8") + "\n")
    except OSError as exc:
        raise AuditError("audit log could not be written") from exc


def chain_head(log: Path) -> tuple[int, str]:
    raise NotImplementedError("W1-C review fix")


def verify_chain(log: Path) -> int | None:
    """Return the 0-based index of the first bad record, or None if the chain is intact.

    A record is bad if it is unparseable, its hash does not match its content, or its prev_hash
    does not match the previous record's hash. Raises AuditError if the log cannot be read.
    """
    try:
        lines = log.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditError("audit log could not be read") from exc
    expected_prev = GENESIS
    for index, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return index
        if not isinstance(record, dict):
            return index
        claimed = record.pop("hash", None)
        if claimed != _sha256(record) or record.get("prev_hash") != expected_prev:
            return index
        expected_prev = claimed
    return None

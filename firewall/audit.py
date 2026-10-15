"""Hash-chained audit log. Stub until stream W1-C replaces it."""

from __future__ import annotations

from pathlib import Path

from firewall.models import Decision, EvalRequest


def append_audit(log: Path, decision: Decision, request: EvalRequest, policy_sha256: str) -> None:
    raise NotImplementedError("W1-C")


def verify_chain(log: Path) -> int | None:
    raise NotImplementedError("W1-C")

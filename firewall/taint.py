"""Value-provenance taint tracking. Stub until stream W1-A replaces it."""

from __future__ import annotations

from collections.abc import Sequence

from firewall.models import Message, ToolCall


def normalise(value: str) -> str:
    raise NotImplementedError("W1-A")


def tainted_arguments(
    call: ToolCall, messages: Sequence[Message], fields: frozenset[str], min_length: int = 6
) -> list[str]:
    raise NotImplementedError("W1-A")

"""Value-provenance taint tracking.

An argument is tainted when its value appears in untrusted content (tool output or retrieved
documents) but nowhere in what the user typed. Matching is lexical on normalised text, so a
paraphrased, split or encoded value evades it (decisions.md#DR-4).
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from firewall.models import Message, Source, ToolCall

# Separators that vary between renderings of the same number: "062-000 1234", "$9,800".
_NOISE = re.compile(r"[\s\-$,]+")

_UNTRUSTED = frozenset({Source.TOOL_OUTPUT, Source.RETRIEVED})


def normalise(value: str) -> str:
    return _NOISE.sub("", value.casefold())


def tainted_arguments(
    call: ToolCall, messages: Sequence[Message], fields: frozenset[str], min_length: int = 6
) -> list[str]:
    """Return the names (never the values) of `fields` arguments sourced from untrusted content.

    Values shorter than `min_length` once normalised are skipped: short strings match by chance.
    """
    untrusted = [normalise(m.content) for m in messages if m.source in _UNTRUSTED]
    user = [normalise(m.content) for m in messages if m.source is Source.USER]
    tainted = []
    for name, value in call.arguments.items():
        if name not in fields or value is None or isinstance(value, bool):
            continue
        needle = normalise(str(value))
        if len(needle) < min_length:
            continue
        if any(needle in text for text in untrusted) and not any(needle in text for text in user):
            tainted.append(name)
    return tainted

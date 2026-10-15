"""Value-provenance taint tracking.

An argument is tainted when its value appears in content the user did not type (tool output,
retrieved documents, or the assistant's own turns, which can echo either) and in no user turn.
Matching is lexical on normalised text, so a paraphrased, split or encoded value evades it
(decisions.md#DR-4).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence

from firewall.models import ArgumentValue, Message, Source, ToolCall

# Fail closed: every source except the user is a taint source, including the assistant.
_UNTRUSTED = frozenset(Source) - {Source.USER}

# Everything except these is formatting: "000–100", "1234​5678", "$9,800", "a.b@c.com".
_SEPARATORS = re.compile(r"[^a-z0-9@]+")


def _fold(value: str) -> str:
    # NFKC turns fullwidth digits and compatibility forms into ASCII before casefolding.
    return unicodedata.normalize("NFKC", value).casefold()


def normalise(value: str) -> str:
    return _SEPARATORS.sub("", _fold(value))


def _argument_text(value: ArgumentValue) -> str:
    # 12345678.0 must compare as "12345678", not "123456780".
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _typed_by_user(needle: str, user_texts: Sequence[str]) -> bool:
    """True when the user typed `needle` as a whole token, allowing separators inside it.

    User text keeps one space per separator run, so "000 100 1234-5678" still clears
    "00010012345678" but "9912345678" does not clear an injected "12345678".
    """
    pattern = re.compile(r"(?<![a-z0-9@])" + " ?".join(map(re.escape, needle)) + r"(?![a-z0-9@])")
    return any(pattern.search(text) for text in user_texts)


def tainted_arguments(
    call: ToolCall, messages: Sequence[Message], fields: frozenset[str], min_length: int = 6
) -> list[str]:
    """Return the names (never the values) of `fields` arguments sourced from untrusted content.

    Values shorter than `min_length` once normalised are skipped: short strings match by chance.
    The untrusted side is a plain substring match (over-matching only adds taint); the user side
    needs a whole-token match so that a longer number the user typed cannot clear the value.
    """
    untrusted = [normalise(m.content) for m in messages if m.source in _UNTRUSTED]
    user = [_SEPARATORS.sub(" ", _fold(m.content)) for m in messages if m.source is Source.USER]
    tainted = []
    for name, value in call.arguments.items():
        if name not in fields or value is None or isinstance(value, bool):
            continue
        needle = normalise(_argument_text(value))
        if len(needle) < min_length:
            continue
        if any(needle in text for text in untrusted) and not _typed_by_user(needle, user):
            tainted.append(name)
    return tainted

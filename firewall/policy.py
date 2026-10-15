"""Policy file loader. Stub until stream W1-B replaces it."""

from __future__ import annotations

from pathlib import Path

from firewall.models import Policy


def load_policy(path: Path) -> Policy:
    raise NotImplementedError("W1-B")

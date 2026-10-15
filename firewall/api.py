"""HTTP API (PLAN.md W3). Stub until the green commit: fails closed by raising."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI


def create_app(settings: Any = None, **_: Any) -> FastAPI:
    raise NotImplementedError("firewall.api.create_app")

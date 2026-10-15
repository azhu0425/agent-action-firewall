"""JSON logging with a per-request id. Log lines carry metadata only (AGENTS.md §2.2)."""

from __future__ import annotations

import json
import logging
import uuid
from contextvars import ContextVar
from datetime import UTC, datetime

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

# Only these keys of `extra={"fields": {...}}` are emitted. Anything else (argument values,
# message content) is dropped, so a careless call site cannot leak data into the logs.
ALLOWED_FIELDS: frozenset[str] = frozenset(
    {"tool", "verdict", "reasons", "latency_ms", "status", "path", "method", "error_type"}
)

_HANDLER_NAME = "firewall-json"


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, message, request_id and allowlisted fields.

    Exception text and stack traces are never emitted: an exception message may carry a value.
    """

    def format(self, record: logging.LogRecord) -> str:
        line: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            # An explicit request_id wins: error handlers log after the request context is gone.
            "request_id": getattr(record, "request_id", None) or request_id_var.get(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            line.update({k: v for k, v in fields.items() if k in ALLOWED_FIELDS})
        return json.dumps(line, default=str)


def configure_logging(level: str) -> None:
    """Install the JSON handler on the root logger, replacing any earlier one we installed."""
    root = logging.getLogger()
    for handler in [h for h in root.handlers if h.get_name() == _HANDLER_NAME]:
        root.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.set_name(_HANDLER_NAME)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)


def new_request_id() -> str:
    return uuid.uuid4().hex

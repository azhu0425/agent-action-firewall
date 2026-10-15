"""JSON logging (PLAN.md W1-D). Log lines carry metadata only, never values (AGENTS.md §2.2)."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator

import pytest

from firewall.observability import (
    JsonFormatter,
    configure_logging,
    new_request_id,
    request_id_var,
)


@pytest.fixture
def captured() -> Iterator[tuple[logging.Logger, io.StringIO]]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("tests.observability")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    yield logger, stream
    logger.removeHandler(handler)
    logger.propagate = True


def test_json_log_lines_include_request_id(captured: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = captured
    token = request_id_var.set("req-123")
    try:
        logger.info("decision made", extra={"fields": {"tool": "transfer_funds"}})
    finally:
        request_id_var.reset(token)

    line = json.loads(stream.getvalue())

    assert line["request_id"] == "req-123"
    assert line["message"] == "decision made"
    assert line["level"] == "INFO"
    assert line["logger"] == "tests.observability"
    assert line["tool"] == "transfer_funds"
    assert "ts" in line


def test_log_request_id_defaults_to_dash_outside_a_request(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured

    logger.info("startup")

    assert json.loads(stream.getvalue())["request_id"] == "-"


def test_log_extra_fields_outside_allowlist_are_dropped(
    captured: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured
    secret = "BSB 062-000 acct 99887766"

    logger.info(
        "decision made",
        extra={"fields": {"verdict": "DENY", "arguments": {"bsb": secret}, "content": secret}},
    )

    output = stream.getvalue()
    line = json.loads(output)
    assert line["verdict"] == "DENY"
    assert "arguments" not in line
    assert "content" not in line
    assert secret not in output


def test_log_line_omits_exception_text(captured: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = captured
    secret = "payee 0491 570 156"

    try:
        raise ValueError(secret)
    except ValueError:
        logger.exception("evaluation failed")

    assert secret not in stream.getvalue()


def test_configure_logging_is_idempotent() -> None:
    root = logging.getLogger()
    before = list(root.handlers)
    original_level = root.level
    try:
        configure_logging("DEBUG")
        configure_logging("WARNING")

        json_handlers = [h for h in root.handlers if isinstance(h.formatter, JsonFormatter)]
        assert len(json_handlers) == 1
        assert root.level == logging.WARNING
    finally:
        root.handlers = before
        root.setLevel(original_level)


UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


@pytest.fixture
def restored_logging() -> Iterator[None]:
    root = logging.getLogger()
    saved_root = (list(root.handlers), root.level)
    saved = {
        name: (list(logging.getLogger(name).handlers), logging.getLogger(name).propagate)
        for name in UVICORN_LOGGERS
    }
    yield
    root.handlers = saved_root[0]
    root.setLevel(saved_root[1])
    for name, (handlers, propagate) in saved.items():
        logging.getLogger(name).handlers = handlers
        logging.getLogger(name).propagate = propagate


def test_configure_logging_routes_uvicorn_errors_through_json_formatter(
    restored_logging: None, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange: what uvicorn's default log config does, a plain handler that prints tracebacks.
    uvicorn_error = logging.getLogger("uvicorn.error")
    uvicorn_error.addHandler(logging.StreamHandler())
    uvicorn_error.propagate = False

    configure_logging("INFO")
    try:
        raise RuntimeError("SECRET-xyz")
    except RuntimeError as exc:
        uvicorn_error.error("Exception in ASGI application", exc_info=exc)

    captured = capsys.readouterr()
    assert "SECRET-xyz" not in captured.err + captured.out
    assert "Exception in ASGI application" in captured.err


def test_configure_logging_replaces_preexisting_root_handlers(
    restored_logging: None, capsys: pytest.CaptureFixture[str]
) -> None:
    # Arrange: a host or harness already put a plain handler on root, which prints tracebacks.
    root = logging.getLogger()
    root.handlers = [logging.StreamHandler()]

    configure_logging("INFO")
    try:
        raise RuntimeError("SECRET-abc")
    except RuntimeError:
        logging.getLogger("tests.observability.host").exception("evaluation failed")

    captured = capsys.readouterr()
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
    assert "SECRET-abc" not in captured.err + captured.out
    assert captured.err.count("evaluation failed") == 1


def test_new_request_id_is_unique_hex() -> None:
    first, second = new_request_id(), new_request_id()

    assert first != second
    assert len(first) == 32
    int(first, 16)

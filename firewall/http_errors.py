"""HTTP error handlers and request ids. Responses never echo input or stack traces (§9)."""

from __future__ import annotations

import logging
import re

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from firewall.observability import new_request_id, request_id_var

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# A loc segment can be a client-supplied dict key or unknown field name. Only identifier-shaped
# segments (the same rule as models.Identifier) and list indexes are echoed back.
_SAFE_LOC_SEGMENT = re.compile(r"^(?:[a-z][a-z0-9_]{0,63}|\[key\])$")
_DEFAULT_CLIENT_MESSAGE = "invalid value"
_CLIENT_MESSAGES: dict[str, str] = {
    "missing": "field required",
    "extra_forbidden": "unexpected field",
    "json_invalid": "malformed JSON",
}


class RequestIdMiddleware:
    """Takes X-Request-ID if well-formed, otherwise generates one; echoes it on the response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        supplied = Headers(scope=scope).get(REQUEST_ID_HEADER, "")
        request_id = supplied if _VALID_REQUEST_ID.fullmatch(supplied) else new_request_id()
        # Kept on the scope too: the 500 handler runs outside this middleware's context.
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                # Read back from state: a route may replace the id with the body's request_id.
                final_id = scope["state"].get("request_id", request_id)
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = final_id
            await send(message)

        token = request_id_var.set(request_id)
        try:
            await self.app(scope, receive, send_with_id)
        finally:
            request_id_var.reset(token)


def install_request_id(app: FastAPI) -> None:
    app.add_middleware(RequestIdMiddleware)


def adopt_request_id(request: Request, request_id: str) -> None:
    """Make `request_id` the call's canonical id for the response header and for log lines."""
    request.state.request_id = request_id
    # No reset needed: sync routes run in a copy of the context on the thread pool, so this set
    # cannot outlive the request. An `async def` caller would need to reset it itself.
    request_id_var.set(request_id)


def _request_id(request: Request) -> str:
    request_id = getattr(request.state, "request_id", None)
    return request_id if isinstance(request_id, str) else new_request_id()


def _route_path(request: Request) -> str:
    # The route template, not the concrete URL: path parameters may carry identifiers.
    return str(getattr(request.scope.get("route"), "path", "-"))


def _safe_loc(loc: tuple[int | str, ...]) -> list[int | str]:
    return [
        part if isinstance(part, int) or _SAFE_LOC_SEGMENT.fullmatch(part) else "<redacted>"
        for part in loc
    ]


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    request_id = _request_id(request)
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    # Only loc/type and a fixed msg: `input`, `ctx` and pydantic's own msg (a validator can put
    # the submitted value into it) would echo what the client sent.
    details = [
        {
            "loc": _safe_loc(tuple(e.get("loc", ()))),
            "type": e.get("type"),
            "msg": _CLIENT_MESSAGES.get(str(e.get("type")), _DEFAULT_CLIENT_MESSAGE),
        }
        for e in errors
    ]
    logger.info(
        "request validation failed",
        extra={
            "request_id": request_id,
            "fields": {"status": 422, "method": request.method, "path": _route_path(request)},
        },
    )
    return JSONResponse(
        status_code=422,
        content={"error": "invalid_request", "request_id": request_id, "details": details},
        headers={REQUEST_ID_HEADER: request_id},
    )


async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    request_id = _request_id(request)
    # Type name only: the exception message may contain argument values (AGENTS.md §2.2).
    logger.error(
        "unhandled error: %s",
        type(exc).__name__,
        extra={
            "request_id": request_id,
            "fields": {
                "status": 500,
                "method": request.method,
                "path": _route_path(request),
                "error_type": type(exc).__name__,
            },
        },
    )
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "request_id": request_id},
        headers={REQUEST_ID_HEADER: request_id},
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(Exception, _unhandled_error)

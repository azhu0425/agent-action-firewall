"""HTTP API: `GET /health` and `POST /v1/evaluate`.

Fails closed at every step: a policy that is missing, invalid or refused for this environment
leaves the app degraded (every call DENY POLICY_UNLOADED), and a decision that cannot be audited
is replaced by DENY EVALUATOR_ERROR, because an unaudited ALLOW must never leave the firewall.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from firewall.audit import append_audit, chain_head, read_records, verify_chain
from firewall.config import Settings, ShadowModeRefused, assert_mode_allowed, get_settings
from firewall.engine import evaluate
from firewall.errors import AuditError, PolicyError
from firewall.http_errors import install_error_handlers, install_request_id
from firewall.models import Decision, EvalRequest, Policy, Reason, Verdict
from firewall.observability import configure_logging
from firewall.policy import load_policy

logger = logging.getLogger(__name__)

PolicyLoader = Callable[[Path], Policy]
AuditWriter = Callable[[Path, Decision, EvalRequest, str], None]


def _startup_policy(settings: Settings, policy_loader: PolicyLoader) -> Policy | None:
    try:
        policy = policy_loader(settings.policy_path)
    except PolicyError:
        logger.error("policy unloaded: every call will be denied")
        return None
    try:
        assert_mode_allowed(settings, policy.mode)
    except ShadowModeRefused:
        logger.error("policy mode refused in this environment: every call will be denied")
        return None
    return policy


_TEXT_FIELDS = ("ts", "request_id", "tool", "agent_role")
_VERDICTS = frozenset(v.value for v in Verdict)


def _public_record(record: dict[str, object]) -> dict[str, object]:
    """Fields the console shows, each type-checked: a record can be tampered with after it was
    written, so anything malformed becomes None rather than reaching the caller (the chain
    status already reports the tampering). args_sha256 is cut to 8 hex chars: the full hash of
    low-entropy arguments (BSB, account, amount) is brute-forceable (decisions.md DR-3)."""
    public: dict[str, object] = {
        key: value if isinstance(value := record.get(key), str) else None for key in _TEXT_FIELDS
    }
    verdict = record.get("verdict")
    public["verdict"] = verdict if isinstance(verdict, str) and verdict in _VERDICTS else None
    reasons = record.get("reasons")
    public["reasons"] = (
        reasons if isinstance(reasons, list) and all(isinstance(r, str) for r in reasons) else None
    )
    shadow = record.get("shadow")
    public["shadow"] = shadow if isinstance(shadow, bool) else None
    args_hash = record.get("args_sha256")
    public["args_sha256"] = args_hash[:8] if isinstance(args_hash, str) else None
    return public


def create_app(
    settings: Settings | None = None,
    *,
    policy_loader: PolicyLoader = load_policy,
    audit_writer: AuditWriter = append_audit,
) -> FastAPI:
    """Build the app. Settings are resolved and the policy loaded at startup, not at import."""
    # append_audit reads the last hash then appends; sync routes run on a thread pool, so the
    # pair is serialised or two concurrent writers would fork the chain.
    audit_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        resolved = settings or get_settings()
        # Here rather than at import: uvicorn applies its own log config first (observability).
        configure_logging(resolved.log_level)
        app.state.settings = resolved
        app.state.policy = _startup_policy(resolved, policy_loader)
        yield

    app = FastAPI(title="Agent Action Firewall", lifespan=lifespan)
    install_request_id(app)
    install_error_handlers(app)

    # API-only service: send a browser that opens the base URL to the interactive docs.
    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/docs")

    @app.get("/health")
    def health(request: Request) -> JSONResponse:
        policy: Policy | None = request.app.state.policy
        if policy is None:
            return JSONResponse(
                status_code=503, content={"status": "degraded", "reason": "policy_unloaded"}
            )
        return JSONResponse(content={"status": "ok", "policy_sha256": policy.sha256})

    # Read-only view for the local operator console. No auth: it is a local demo, bound to
    # 127.0.0.1 in compose (operate.md). Production would put this behind SSO + RBAC.
    @app.get("/v1/audit")
    def audit_trail(
        request: Request, limit: Annotated[int, Query(ge=1, le=200)] = 50
    ) -> JSONResponse:
        log: Path = request.app.state.settings.audit_log
        try:
            with audit_lock:
                first_bad = verify_chain(log) if log.exists() else None
                count, head = chain_head(log) if log.exists() and first_bad is None else (0, None)
                records = read_records(log)
        except AuditError:
            logger.error(
                "audit read failed",
                extra={
                    "request_id": request.state.request_id,
                    "fields": {"error_type": "AuditError"},
                },
            )
            return JSONResponse(
                status_code=500,
                content={"error": "audit_unavailable", "request_id": request.state.request_id},
            )
        newest = [_public_record(r) for r in reversed(records[-limit:])]
        return JSONResponse(
            content={
                "records": newest,
                "chain": {
                    "ok": first_bad is None,
                    "count": count if first_bad is None else len(records),
                    "head": head if first_bad is None else None,
                    "first_bad": first_bad,
                },
            }
        )

    @app.post("/v1/evaluate")
    def evaluate_call(body: EvalRequest, request: Request) -> Decision:
        started = time.perf_counter()
        resolved: Settings = request.app.state.settings
        policy: Policy | None = request.app.state.policy
        # One canonical id per call: a body id (already pattern-validated) wins over X-Request-ID,
        # and the middleware echoes whatever is on request.state in the response header.
        if body.request_id is None:
            body = body.model_copy(update={"request_id": request.state.request_id})
        else:
            request.state.request_id = body.request_id
        decision = evaluate(body, policy)
        policy_sha256 = policy.sha256 if policy is not None else ""
        try:
            with audit_lock:
                audit_writer(resolved.audit_log, decision, body, policy_sha256)
        except AuditError:
            logger.error(
                "audit write failed: decision replaced by DENY",
                extra={"request_id": decision.request_id, "fields": {"error_type": "AuditError"}},
            )
            decision = Decision(
                request_id=decision.request_id,
                verdict=Verdict.DENY,
                reasons=[Reason.EVALUATOR_ERROR],
                policy_sha256=policy_sha256 or None,
            )
        logger.info(
            "decision",
            extra={
                "request_id": decision.request_id,
                "fields": {
                    "tool": body.call.tool,
                    "verdict": decision.verdict.value,
                    "reasons": [reason.value for reason in decision.reasons],
                    "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                },
            },
        )
        return decision

    return app


app = create_app()

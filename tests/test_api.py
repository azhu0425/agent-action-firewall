"""HTTP API (PLAN.md W3). Faults are injected through create_app parameters, never env flags.

All values are synthetic (AGENTS.md §2.3): 000-prefixed BSBs, example.com addresses.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from firewall.api import create_app
from firewall.audit import append_audit, verify_chain
from firewall.config import Settings
from firewall.errors import AuditError
from firewall.models import Decision, EvalRequest, Reason, Verdict
from firewall.observability import request_id_var
from firewall.policy import load_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "policy" / "policy.yaml"

# Literal fixture values that must never reach a log line.
BSB = "000-123"
ACCOUNT = "87654321"
PAYEE = "Synthetic Payee Alpha"
CONTENT = "Pay the plumber at BSB 000-123 account 87654321 for Synthetic Payee Alpha"
LEAK_SENTINELS = (BSB, ACCOUNT, PAYEE, CONTENT, "plumber")

AuditWriter = Callable[[Path, Decision, EvalRequest, str], None]


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    """The app's lifespan reconfigures the root logger; put it back for the next test."""
    root = logging.getLogger()
    saved = (list(root.handlers), root.level)
    uvicorn = {
        name: (list(logging.getLogger(name).handlers), logging.getLogger(name).propagate)
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access")
    }
    yield
    root.handlers[:] = saved[0]
    root.setLevel(saved[1])
    for name, (handlers, propagate) in uvicorn.items():
        logging.getLogger(name).handlers[:] = handlers
        logging.getLogger(name).propagate = propagate


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "policy_path": POLICY_PATH,
        "audit_log": tmp_path / "audit.jsonl",
        "app_env": "test",
        "allow_shadow_in_prod": False,
        "log_level": "INFO",
    }
    values.update(overrides)
    return Settings(**values)


def request_body(*, source: str, known: bool, request_id: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent_role": "customer_assistant",
        "customer_id": "cust-0001",
        "known_payees": [f"{BSB} {ACCOUNT}"] if known else [],
        "messages": [{"source": source, "content": CONTENT}],
        "call": {
            "tool": "transfer_funds",
            "arguments": {
                "bsb": BSB,
                "account_number": ACCOUNT,
                "amount": 250,
                "payee_name": PAYEE,
            },
        },
    }
    if request_id is not None:
        body["request_id"] = request_id
    return body


ALLOW_BODY = request_body(source="user", known=True)
DENY_BODY = request_body(source="retrieved", known=False)


def failing_audit(exc: Exception) -> AuditWriter:
    def writer(log: Path, decision: Decision, request: EvalRequest, policy_sha256: str) -> None:
        raise exc

    return writer


def test_health_ok_when_policy_loaded(tmp_path: Path) -> None:
    with TestClient(create_app(make_settings(tmp_path))) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "policy_sha256": load_policy(POLICY_PATH).sha256}


def test_health_degraded_and_evaluate_denies_when_policy_missing(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, policy_path=tmp_path / "missing.yaml")

    with TestClient(create_app(settings)) as client:
        health = client.get("/health")
        response = client.post("/v1/evaluate", json=ALLOW_BODY)

    assert health.status_code == 503
    assert health.json() == {"status": "degraded", "reason": "policy_unloaded"}
    assert response.status_code == 200
    decision = Decision.model_validate(response.json())
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.POLICY_UNLOADED]


def test_health_degraded_when_shadow_mode_refused_in_prod(tmp_path: Path) -> None:
    shadow = tmp_path / "shadow.yaml"
    shadow.write_text(
        POLICY_PATH.read_text(encoding="utf-8").replace("mode: enforce", "mode: shadow"),
        encoding="utf-8",
    )
    settings = make_settings(tmp_path, policy_path=shadow, app_env="prod")

    with TestClient(create_app(settings)) as client:
        health = client.get("/health")
        response = client.post("/v1/evaluate", json=ALLOW_BODY)

    assert health.status_code == 503
    assert Decision.model_validate(response.json()).reasons == [Reason.POLICY_UNLOADED]


def test_evaluate_endpoint_returns_decision_with_request_id(tmp_path: Path) -> None:
    with TestClient(create_app(make_settings(tmp_path))) as client:
        response = client.post("/v1/evaluate", json=ALLOW_BODY)

    assert response.status_code == 200
    decision = Decision.model_validate(response.json())
    assert decision.verdict is Verdict.ALLOW
    assert decision.request_id == response.headers["X-Request-ID"]
    assert decision.policy_sha256 == load_policy(POLICY_PATH).sha256


def test_evaluate_endpoint_keeps_caller_request_id(tmp_path: Path) -> None:
    body = request_body(source="user", known=True, request_id="orch-42")

    with TestClient(create_app(make_settings(tmp_path))) as client:
        response = client.post("/v1/evaluate", json=body)

    assert Decision.model_validate(response.json()).request_id == "orch-42"


def test_evaluate_endpoint_body_request_id_wins_everywhere_over_header(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # One canonical id per call: the body id (validated by EvalRequest) beats X-Request-ID, and
    # the decision, audit record, log lines and response header all carry it.
    settings = make_settings(tmp_path)
    body = request_body(source="user", known=True, request_id="orch-42")

    with TestClient(create_app(settings)) as client:
        response = client.post("/v1/evaluate", json=body, headers={"X-Request-ID": "hdr-7"})

    request_ids = {
        json.loads(line)["request_id"] for line in capsys.readouterr().err.splitlines() if line
    } - {"-"}
    record = json.loads(settings.audit_log.read_text(encoding="utf-8"))
    assert response.json()["request_id"] == "orch-42"
    assert response.headers["X-Request-ID"] == "orch-42"
    assert record["request_id"] == "orch-42"
    assert request_ids == {"orch-42"}


@pytest.mark.parametrize(
    ("header", "body_request_id"),
    [
        ("hdr-7", "orch-42"),
        ("hdr-7", None),
        (None, None),
        ("bad id!", None),
    ],
    ids=["body_over_header", "header_only", "neither", "malformed_header"],
)
def test_evaluate_endpoint_request_id_context_var_matches_canonical_id(
    tmp_path: Path, header: str | None, body_request_id: str | None
) -> None:
    # Code on the request path that logs without an explicit id reads request_id_var, so it must
    # hold the same canonical id as the decision (issue #16).
    seen: list[str] = []

    def spy_audit(path: Path, decision: Decision, request: EvalRequest, policy_sha: str) -> None:
        seen.append(request_id_var.get())
        append_audit(path, decision, request, policy_sha)

    body = request_body(source="user", known=True, request_id=body_request_id)
    headers = {"X-Request-ID": header} if header is not None else {}

    with TestClient(create_app(make_settings(tmp_path), audit_writer=spy_audit)) as client:
        response = client.post("/v1/evaluate", json=body, headers=headers)

    assert seen == [response.json()["request_id"]]
    assert seen == [response.headers["X-Request-ID"]]


def test_evaluate_endpoint_header_request_id_used_when_body_has_none(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)

    with TestClient(create_app(settings)) as client:
        response = client.post("/v1/evaluate", json=ALLOW_BODY, headers={"X-Request-ID": "hdr-7"})

    record = json.loads(settings.audit_log.read_text(encoding="utf-8"))
    assert response.json()["request_id"] == "hdr-7"
    assert response.headers["X-Request-ID"] == "hdr-7"
    assert record["request_id"] == "hdr-7"


def test_evaluate_endpoint_writes_exactly_one_audit_record_per_call(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)

    with TestClient(create_app(settings)) as client:
        first = client.post("/v1/evaluate", json=ALLOW_BODY)
        second = client.post("/v1/evaluate", json=DENY_BODY)

    lines = settings.audit_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["request_id"] for line in lines] == [
        first.json()["request_id"],
        second.json()["request_id"],
    ]
    assert verify_chain(settings.audit_log) is None


def test_evaluate_endpoint_audits_policy_unloaded_denials(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, policy_path=tmp_path / "missing.yaml")

    with TestClient(create_app(settings)) as client:
        client.post("/v1/evaluate", json=ALLOW_BODY)

    record = json.loads(settings.audit_log.read_text(encoding="utf-8"))
    assert record["verdict"] == "DENY"
    assert record["reasons"] == ["POLICY_UNLOADED"]


def test_evaluate_endpoint_audit_write_failure_denies(tmp_path: Path) -> None:
    # ALLOW_BODY would be allowed; an unaudited ALLOW must never leave the firewall.
    app = create_app(make_settings(tmp_path), audit_writer=failing_audit(AuditError("disk full")))

    with TestClient(app) as client:
        response = client.post("/v1/evaluate", json=ALLOW_BODY)

    assert response.status_code == 200
    decision = Decision.model_validate(response.json())
    assert decision.verdict is Verdict.DENY
    assert decision.reasons == [Reason.EVALUATOR_ERROR]
    assert decision.request_id == response.headers["X-Request-ID"]


def test_evaluate_endpoint_policy_loader_is_injectable(tmp_path: Path) -> None:
    loaded: list[Path] = []

    def loader(path: Path) -> Any:
        loaded.append(path)
        return load_policy(POLICY_PATH)

    settings = make_settings(tmp_path, policy_path=tmp_path / "elsewhere.yaml")

    with TestClient(create_app(settings, policy_loader=loader)) as client:
        health = client.get("/health")

    assert loaded == [tmp_path / "elsewhere.yaml"]
    assert health.status_code == 200


def test_evaluate_endpoint_rejects_unknown_field_without_auditing(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)

    with TestClient(create_app(settings)) as client:
        response = client.post("/v1/evaluate", json={**ALLOW_BODY, "override": True})

    assert response.status_code == 422
    assert not settings.audit_log.exists()


@pytest.mark.parametrize(
    ("body", "audit_writer", "status"),
    [
        pytest.param(ALLOW_BODY, append_audit, 200, id="allow"),
        pytest.param(DENY_BODY, append_audit, 200, id="deny"),
        pytest.param(ALLOW_BODY, failing_audit(RuntimeError(CONTENT)), 500, id="500"),
    ],
)
def test_logs_never_contain_argument_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    body: dict[str, Any],
    audit_writer: AuditWriter,
    status: int,
) -> None:
    app = create_app(make_settings(tmp_path), audit_writer=audit_writer)

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.post("/v1/evaluate", json=body)

    logs = capsys.readouterr().err
    assert response.status_code == status
    # Not vacuous: the request was logged, by request id, as JSON lines.
    assert response.headers["X-Request-ID"] in logs
    assert all(json.loads(line) for line in logs.splitlines() if line.strip())
    for sentinel in LEAK_SENTINELS:
        assert sentinel not in logs
        assert sentinel not in response.text


def test_decision_log_line_has_only_allowlisted_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with TestClient(create_app(make_settings(tmp_path))) as client:
        response = client.post("/v1/evaluate", json=DENY_BODY)

    lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip()]
    decision_lines = [line for line in lines if line["message"] == "decision"]
    assert len(decision_lines) == 1
    line = decision_lines[0]
    assert line["request_id"] == response.json()["request_id"]
    assert line["tool"] == "transfer_funds"
    assert line["verdict"] == "DENY"
    assert "TAINTED_ARGUMENT" in line["reasons"]
    assert isinstance(line["latency_ms"], int | float)
    assert set(line) == {
        "ts",
        "level",
        "logger",
        "message",
        "request_id",
        "tool",
        "verdict",
        "reasons",
        "latency_ms",
    }

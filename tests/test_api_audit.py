"""GET /v1/audit: recent value-free audit records plus chain status, for the operator console."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from test_api import ACCOUNT, BSB, CONTENT, PAYEE, make_settings, request_body

from firewall.api import create_app


def _run_calls(client: TestClient, count: int) -> None:
    for _ in range(count):
        assert client.post("/v1/evaluate", json=request_body(source="user", known=True)).is_success


def test_audit_endpoint_returns_recent_value_free_records(tmp_path: Path) -> None:
    with TestClient(create_app(make_settings(tmp_path))) as client:
        _run_calls(client, 3)
        response = client.get("/v1/audit")

    body = response.json()
    assert response.status_code == 200
    assert body["chain"] == {
        "ok": True,
        "count": 3,
        "head": body["chain"]["head"],
        "first_bad": None,
    }
    assert len(body["records"]) == 3
    newest = body["records"][0]
    assert {"ts", "request_id", "tool", "verdict", "reasons", "args_sha256"} <= set(newest)
    assert len(newest["args_sha256"]) == 8
    for value in (BSB, ACCOUNT, PAYEE, CONTENT):
        assert value not in response.text


def test_audit_endpoint_returns_newest_first_and_respects_limit(tmp_path: Path) -> None:
    with TestClient(create_app(make_settings(tmp_path))) as client:
        _run_calls(client, 5)
        records = client.get("/v1/audit", params={"limit": 2}).json()["records"]
        everything = client.get("/v1/audit").json()["records"]

    assert len(records) == 2
    assert records[0]["ts"] >= records[1]["ts"]
    assert records == everything[:2]


def test_audit_endpoint_limit_is_capped(tmp_path: Path) -> None:
    with TestClient(create_app(make_settings(tmp_path))) as client:
        too_big = client.get("/v1/audit", params={"limit": 201})
        too_small = client.get("/v1/audit", params={"limit": 0})

    assert too_big.status_code == 422
    assert too_small.status_code == 422


def test_audit_endpoint_empty_log(tmp_path: Path) -> None:
    with TestClient(create_app(make_settings(tmp_path))) as client:
        response = client.get("/v1/audit")

    assert response.status_code == 200
    assert response.json()["records"] == []
    assert response.json()["chain"]["ok"] is True
    assert response.json()["chain"]["count"] == 0


def test_audit_endpoint_sanitises_tampered_fields(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings)) as client:
        _run_calls(client, 2)
        lines = settings.audit_log.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered.update({"verdict": "BOGUS", "reasons": "not-a-list", "tool": {"x": 1}})
        lines[0] = json.dumps(tampered)
        settings.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        response = client.get("/v1/audit")

    body = response.json()
    assert response.status_code == 200
    assert body["chain"]["ok"] is False
    oldest = body["records"][-1]
    assert oldest["verdict"] is None
    assert oldest["reasons"] is None
    assert oldest["tool"] is None


def test_audit_endpoint_reports_broken_chain(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    with TestClient(create_app(settings)) as client:
        _run_calls(client, 3)
        lines = settings.audit_log.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["verdict"] = "ALLOW" if tampered["verdict"] != "ALLOW" else "DENY"
        lines[1] = json.dumps(tampered)
        settings.audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        response = client.get("/v1/audit")

    assert response.status_code == 200
    assert response.json()["chain"]["ok"] is False
    assert response.json()["chain"]["first_bad"] == 1
    assert response.json()["chain"]["head"] is None

"""HTTP error handlers and request ids, on a throwaway app (PLAN.md W1-D, AGENTS.md §9)."""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict, field_validator

from firewall.http_errors import install_error_handlers, install_request_id

SECRET = "SYNTH-0491570156-acct-99887766"


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: int


class Checked(BaseModel):
    payee: str

    @field_validator("payee")
    @classmethod
    def _reject(cls, value: str) -> str:
        # A careless validator that puts the submitted value into its error message.
        raise ValueError(f"bad {value}")


def make_app() -> FastAPI:
    app = FastAPI()
    install_error_handlers(app)
    install_request_id(app)

    @app.post("/echo")
    def echo(body: Body) -> dict[str, int]:
        return {"amount": body.amount}

    @app.post("/checked")
    def checked(body: Checked) -> dict[str, str]:
        return {"payee": body.payee}

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError(SECRET)

    return app


def test_validation_error_response_does_not_echo_input() -> None:
    client = TestClient(make_app())

    response = client.post("/echo", json={"amount": SECRET})

    assert response.status_code == 422
    assert SECRET not in response.text
    body = response.json()
    assert body["error"] == "invalid_request"
    assert body["request_id"] == response.headers["X-Request-ID"]
    assert body["details"][0]["loc"] == ["body", "amount"]
    assert set(body["details"][0]) == {"loc", "type", "msg"}


def test_validation_error_loc_does_not_echo_unknown_keys() -> None:
    client = TestClient(make_app())

    response = client.post("/echo", json={"amount": 1, SECRET: 1})

    assert response.status_code == 422
    assert SECRET not in response.text


def test_validation_error_msg_does_not_echo_value_from_validator() -> None:
    client = TestClient(make_app())

    response = client.post("/checked", json={"payee": SECRET})

    assert response.status_code == 422
    assert SECRET not in response.text
    assert response.json()["details"][0]["type"] == "value_error"


def test_validation_error_identifier_shaped_unknown_key_is_named_in_loc() -> None:
    # Identifier-shaped names are treated as metadata, as models.Identifier does for argument
    # names; only non-identifier keys are redacted.
    client = TestClient(make_app())

    response = client.post("/echo", json={"amount": 1, "unexpected_field": 1})

    assert response.status_code == 422
    detail = response.json()["details"][0]
    assert detail["loc"] == ["body", "unexpected_field"]
    assert detail["type"] == "extra_forbidden"


def test_validation_error_non_identifier_unknown_key_is_redacted_in_loc() -> None:
    client = TestClient(make_app())

    response = client.post("/echo", json={"amount": 1, SECRET: 1})

    assert response.json()["details"][0]["loc"] == ["body", "<redacted>"]


def test_validation_error_for_malformed_json_does_not_echo_body() -> None:
    client = TestClient(make_app())

    response = client.post(
        "/echo", content=f'{{"amount": "{SECRET}"', headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 422
    assert SECRET not in response.text


def test_unhandled_error_returns_generic_500_with_request_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = TestClient(make_app(), raise_server_exceptions=False)

    with caplog.at_level(logging.ERROR):
        response = client.get("/boom", headers={"X-Request-ID": "req-500"})

    assert response.status_code == 500
    assert response.json() == {"error": "internal_error", "request_id": "req-500"}
    assert response.headers["X-Request-ID"] == "req-500"
    assert SECRET not in response.text
    assert SECRET not in caplog.text
    assert "RuntimeError" in caplog.text


def test_valid_request_id_header_is_echoed() -> None:
    client = TestClient(make_app())

    response = client.post("/echo", json={"amount": 1}, headers={"X-Request-ID": "abc.DEF_1-2"})

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "abc.DEF_1-2"


@pytest.mark.parametrize("header", ["has spaces", "x" * 65, "semi;colon", ""])
def test_invalid_request_id_header_is_replaced(header: str) -> None:
    client = TestClient(make_app())

    response = client.post("/echo", json={"amount": 1}, headers={"X-Request-ID": header})

    replaced = response.headers["X-Request-ID"]
    assert replaced != header
    assert len(replaced) == 32
    int(replaced, 16)


def test_request_id_generated_when_header_absent() -> None:
    client = TestClient(make_app())

    first = client.post("/echo", json={"amount": 1}).headers["X-Request-ID"]
    second = client.post("/echo", json={"amount": 1}).headers["X-Request-ID"]

    assert first != second

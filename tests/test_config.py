"""Settings and the shadow-in-prod guard (PLAN.md W1-D)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from firewall.config import Settings, ShadowModeRefused, assert_mode_allowed, get_settings
from firewall.errors import FirewallError


def settings(**fields: object) -> Settings:
    # _env_file=None: a developer's local .env must not change test outcomes.
    return Settings(_env_file=None, **fields)  # type: ignore[arg-type]


def test_settings_defaults_match_env_example(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "FIREWALL_POLICY_PATH",
        "FIREWALL_AUDIT_LOG",
        "APP_ENV",
        "FIREWALL_ALLOW_SHADOW_IN_PROD",
        "LOG_LEVEL",
    ):
        monkeypatch.delenv(name, raising=False)

    result = settings()

    assert result.policy_path == Path("policy/policy.yaml")
    assert result.audit_log == Path("audit/audit.jsonl")
    assert result.app_env == "dev"
    assert result.allow_shadow_in_prod is False
    assert result.log_level == "INFO"


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIREWALL_POLICY_PATH", "other/policy.yaml")
    monkeypatch.setenv("FIREWALL_AUDIT_LOG", "other/audit.jsonl")
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("FIREWALL_ALLOW_SHADOW_IN_PROD", "true")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    result = settings()

    assert result.policy_path == Path("other/policy.yaml")
    assert result.audit_log == Path("other/audit.jsonl")
    assert result.app_env == "prod"
    assert result.allow_shadow_in_prod is True
    assert result.log_level == "DEBUG"


def test_settings_invalid_app_env_rejected_at_startup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")

    with pytest.raises(ValidationError):
        settings()


def test_shadow_mode_refused_in_prod_without_override() -> None:
    prod = settings(app_env="prod", allow_shadow_in_prod=False)

    with pytest.raises(ShadowModeRefused):
        assert_mode_allowed(prod, "shadow")


def test_shadow_mode_refused_is_a_firewall_error() -> None:
    assert issubclass(ShadowModeRefused, FirewallError)


def test_shadow_mode_allowed_in_prod_with_override() -> None:
    prod = settings(app_env="prod", allow_shadow_in_prod=True)

    assert_mode_allowed(prod, "shadow")


@pytest.mark.parametrize(("app_env", "mode"), [("dev", "shadow"), ("prod", "enforce")])
def test_mode_allowed_outside_shadow_in_prod(app_env: str, mode: str) -> None:
    assert_mode_allowed(settings(app_env=app_env), mode)


def test_get_settings_is_cached() -> None:
    get_settings.cache_clear()
    try:
        assert get_settings() is get_settings()
    finally:
        get_settings.cache_clear()

"""Runtime settings from env vars (names as in `.env.example`), validated at startup."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from firewall.errors import FirewallError


class ShadowModeRefused(FirewallError):
    """Shadow mode was requested in prod without FIREWALL_ALLOW_SHADOW_IN_PROD=true."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    policy_path: Path = Field(
        default=Path("policy/policy.yaml"), validation_alias="FIREWALL_POLICY_PATH"
    )
    audit_log: Path = Field(
        default=Path("audit/audit.jsonl"), validation_alias="FIREWALL_AUDIT_LOG"
    )
    app_env: Literal["dev", "test", "prod"] = Field(default="dev", validation_alias="APP_ENV")
    allow_shadow_in_prod: bool = Field(
        default=False, validation_alias="FIREWALL_ALLOW_SHADOW_IN_PROD"
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO", validation_alias="LOG_LEVEL"
    )


def assert_mode_allowed(settings: Settings, mode: Literal["enforce", "shadow"]) -> None:
    """Raise ShadowModeRefused if `mode` may not run in this environment.

    Shadow mode ALLOWs everything, so in prod it needs an explicit, separate opt-in.
    """
    if mode == "shadow" and settings.app_env == "prod" and not settings.allow_shadow_in_prod:
        raise ShadowModeRefused("shadow mode is refused in prod without the override")


@lru_cache
def get_settings() -> Settings:
    return Settings()

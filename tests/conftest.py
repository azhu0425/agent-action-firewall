"""Shared fixtures. Integrator-owned: streams add fixtures in their own test files."""

from __future__ import annotations

from pathlib import Path

import pytest

from firewall.models import Policy, RolePolicy

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def policy() -> Policy:
    """A valid policy built in code, so rule and engine tests don't depend on the YAML loader."""
    return Policy(
        version="test",
        mode="enforce",
        roles={
            "customer_assistant": RolePolicy(
                allowed_tools=["get_account_summary", "transfer_funds", "send_email"],
                soft_cap_aud=1000,
                hard_cap_aud=5000,
            ),
            "support_agent": RolePolicy(
                allowed_tools=["get_account_summary", "send_email", "update_contact_details"],
                soft_cap_aud=0,
                hard_cap_aud=0,
            ),
        },
        high_risk_tools=["transfer_funds", "send_email", "update_contact_details"],
        taint_fields=["bsb", "account_number", "to", "email", "phone"],
        bank_email_domains=["bank.example.com"],
        min_taint_length=6,
    )

"""Policy loader: a valid file loads with its hash; anything else raises PolicyError."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from firewall.errors import PolicyError
from firewall.models import Policy
from firewall.policy import load_policy

VALID_YAML = """\
version: "t1"
mode: enforce
roles:
  customer_assistant:
    allowed_tools: [get_account_summary, transfer_funds]
    soft_cap_aud: 1000
    hard_cap_aud: 5000
high_risk_tools: [transfer_funds]
taint_fields: [bsb, account_number]
bank_email_domains: [bank.example.com]
min_taint_length: 6
"""

# A distinctive synthetic value that must never surface in an error message (AGENTS.md §2.2).
SECRET_MARKER = "ZQX-SYNTHETIC-7731"


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_bytes(text.encode("utf-8"))
    return path


def test_load_policy_valid_file_returns_policy_with_sha256(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML)

    result = load_policy(path)

    assert isinstance(result, Policy)
    assert result.version == "t1"
    assert result.roles["customer_assistant"].hard_cap_aud == 5000
    assert result.sha256 == hashlib.sha256(VALID_YAML.encode("utf-8")).hexdigest()


def test_load_policy_missing_file_raises_policy_error(tmp_path: Path) -> None:
    path = tmp_path / "absent.yaml"

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_unknown_key_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML + "allow_everything: true\n")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_negative_amount_cap_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML.replace("soft_cap_aud: 1000", "soft_cap_aud: -1"))

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_rejects_declared_sha256(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML + 'sha256: "0000"\n')

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_invalid_yaml_raises_policy_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "roles: [unclosed\n")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_non_mapping_document_raises_policy_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "- just\n- a\n- list\n")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_error_message_has_no_file_values(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML.replace('version: "t1"', f"version: [{SECRET_MARKER}]"))

    with pytest.raises(PolicyError) as excinfo:
        load_policy(path)

    assert SECRET_MARKER not in str(excinfo.value)


def test_load_policy_shipped_policy_file_loads(repo_root: Path) -> None:
    result = load_policy(repo_root / "policy" / "policy.yaml")

    assert result.mode == "enforce"
    assert set(result.roles) == {"customer_assistant", "support_agent"}
    assert len(result.sha256) == 64


def test_load_policy_shipped_policy_matches_fixture(repo_root: Path, policy: Policy) -> None:
    result = load_policy(repo_root / "policy" / "policy.yaml")

    assert result.model_dump(exclude={"version", "sha256"}) == policy.model_dump(
        exclude={"version", "sha256"}
    )


def test_load_policy_oversized_file_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML + "#" * 70_000 + "\n")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_deep_nesting_raises_policy_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "version: " + "[" * 20_000 + "]" * 20_000 + "\n")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_duplicate_key_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML + "mode: shadow\n")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_yaml_error_has_no_marker_or_context(tmp_path: Path) -> None:
    path = _write(tmp_path, f"roles: [{SECRET_MARKER}\n  : : :\n")

    with pytest.raises(PolicyError) as excinfo:
        load_policy(path)

    assert SECRET_MARKER not in str(excinfo.value)
    assert excinfo.value.__context__ is None


def test_load_policy_validation_error_has_no_context(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML.replace('version: "t1"', f"version: [{SECRET_MARKER}]"))

    with pytest.raises(PolicyError) as excinfo:
        load_policy(path)

    assert excinfo.value.__context__ is None


def test_load_policy_empty_file_raises_policy_error(tmp_path: Path) -> None:
    path = _write(tmp_path, "")

    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_hard_cap_below_soft_cap_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, VALID_YAML.replace("hard_cap_aud: 5000", "hard_cap_aud: 500"))

    with pytest.raises(PolicyError):
        load_policy(path)

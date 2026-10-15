from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

import firewall

VERIFY_PATH = Path(__file__).resolve().parent.parent / "scripts" / "verify.py"


def load_verify():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("verify_under_test", VERIFY_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_package_exposes_version() -> None:
    assert firewall.__version__ == "0.1.0"


def test_verify_script_exits_nonzero_when_a_step_fails(capsys: pytest.CaptureFixture[str]) -> None:
    verify = load_verify()
    steps = {
        "passes": [sys.executable, "-c", "raise SystemExit(0)"],
        "fails": [sys.executable, "-c", "raise SystemExit(3)"],
    }

    code = verify.run_steps(steps, enabled=["passes", "fails"], strict=False)

    assert code != 0
    assert "fails" in capsys.readouterr().out


def test_verify_reports_skipped_steps_and_fails_on_skip_when_strict(
    capsys: pytest.CaptureFixture[str],
) -> None:
    verify = load_verify()
    steps = {
        "passes": [sys.executable, "-c", "raise SystemExit(0)"],
        "later": [sys.executable, "-c", "raise SystemExit(0)"],
    }

    lenient = verify.run_steps(steps, enabled=["passes"], strict=False)
    lenient_out = capsys.readouterr().out
    strict = verify.run_steps(steps, enabled=["passes"], strict=True)

    assert lenient == 0
    assert "SKIPPED" in lenient_out
    assert strict != 0

"""CLI: replay, verify-audit and demo (PLAN.md W3). All values are synthetic (AGENTS.md §2.3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from firewall.audit import append_audit, chain_head
from firewall.cli import main
from firewall.models import Decision, EvalRequest, Reason, Verdict

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = REPO_ROOT / "policy" / "policy.yaml"

SECRET_ACCOUNT = "55501234"
SECRET_CONTENT = "SENTINEL transfer to BSB 000-700 account 55501234"
SECRET_DESCRIPTION = "SENTINEL-DESCRIPTION"


def trace(
    case_id: str, *, source: str, decision: str, reasons: list[str], known: bool = True
) -> dict[str, Any]:
    return {
        "id": case_id,
        "description": SECRET_DESCRIPTION,
        "request": {
            "request_id": case_id,
            "agent_role": "customer_assistant",
            "customer_id": "cust-0001",
            "known_payees": ["000-700 55501234"] if known else [],
            "messages": [{"source": source, "content": SECRET_CONTENT}],
            "call": {
                "tool": "transfer_funds",
                "arguments": {"bsb": "000-700", "account_number": SECRET_ACCOUNT, "amount": 120},
            },
        },
        "expected": {"decision": decision, "reasons": reasons},
    }


def write_traces(path: Path, rows: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return path


def test_cli_replay_prints_report_and_exits_zero_when_expectations_met(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    traces = write_traces(
        tmp_path / "traces.jsonl",
        [
            trace("cli-ok-1", source="user", decision="ALLOW", reasons=[]),
            trace(
                "cli-ok-2",
                source="retrieved",
                decision="DENY",
                reasons=["TAINTED_ARGUMENT"],
                known=False,
            ),
        ],
    )

    code = main(["replay", str(traces), "--policy", str(POLICY_PATH)])

    out = capsys.readouterr().out
    assert code == 0
    assert "cli-ok-1" in out and "cli-ok-2" in out
    assert "FAIL" not in out
    for secret in (SECRET_ACCOUNT, SECRET_CONTENT, SECRET_DESCRIPTION, "000-700"):
        assert secret not in out


def test_cli_replay_exits_nonzero_on_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    traces = write_traces(
        tmp_path / "traces.jsonl",
        [
            trace("cli-ok", source="user", decision="ALLOW", reasons=[]),
            trace("cli-bad", source="retrieved", decision="ALLOW", reasons=[], known=False),
        ],
    )

    code = main(["replay", str(traces), "--policy", str(POLICY_PATH)])

    out = capsys.readouterr().out
    assert code == 1
    bad_line = next(line for line in out.splitlines() if line.startswith("cli-bad"))
    assert "FAIL" in bad_line
    assert "DENY" in bad_line


def test_cli_replay_human_corpus_meets_expectations(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "replay",
            str(REPO_ROOT / "eval" / "corpus" / "attack.jsonl"),
            "--policy",
            str(POLICY_PATH),
        ]
    )

    assert code == 0
    assert "atk-001" in capsys.readouterr().out


def test_cli_replay_malformed_trace_exits_two_without_echo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    row = trace("cli-x", source="user", decision="ALLOW", reasons=[])
    row["request"]["call"]["arguments"]["account_number"] = [SECRET_ACCOUNT]
    traces = write_traces(tmp_path / "traces.jsonl", [row])

    code = main(["replay", str(traces), "--policy", str(POLICY_PATH)])

    captured = capsys.readouterr()
    assert code == 2
    assert SECRET_ACCOUNT not in captured.out + captured.err


def test_cli_replay_missing_policy_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    traces = write_traces(
        tmp_path / "traces.jsonl", [trace("cli-ok", source="user", decision="ALLOW", reasons=[])]
    )

    code = main(["replay", str(traces), "--policy", str(tmp_path / "missing.yaml")])

    assert code == 2


def write_audit(log: Path, count: int) -> None:
    row = trace("aud", source="user", decision="ALLOW", reasons=[])
    request = EvalRequest.model_validate(row["request"])
    for index in range(count):
        decision = Decision(
            request_id=f"aud-{index}", verdict=Verdict.DENY, reasons=[Reason.NEW_PAYEE]
        )
        append_audit(log, decision, request, "a" * 64)


def test_cli_verify_audit_intact_chain_prints_head_and_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "audit.jsonl"
    write_audit(log, 3)

    code = main(["verify-audit", str(log)])

    count, head = chain_head(log)
    assert code == 0
    assert capsys.readouterr().out.strip() == f"OK {count} records, head {head}"


def test_cli_verify_audit_broken_chain_reports_index_and_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = tmp_path / "audit.jsonl"
    write_audit(log, 3)
    lines = log.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"verdict":"DENY"', '"verdict":"ALLOW"')
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    code = main(["verify-audit", str(log)])

    assert code == 1
    assert capsys.readouterr().out.strip() == "BROKEN at record 1"


def test_cli_verify_audit_missing_log_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["verify-audit", str(tmp_path / "missing.jsonl")])

    assert code == 2


def test_cli_demo_shows_money_moving_only_without_firewall(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["demo", "--policy", str(POLICY_PATH)])

    out = capsys.readouterr().out
    without, _, with_firewall = out.partition("with firewall")
    assert code == 0
    assert "firewall: off" in without
    assert "money moved: $9,800.00" in without
    assert "firewall: DENY" in with_firewall
    assert "TAINTED_ARGUMENT" in with_firewall
    assert "money moved: none" in with_firewall
    assert "12345678" not in out


def test_cli_demo_with_firewall_only(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["demo", "--with-firewall", "--policy", str(POLICY_PATH)])

    out = capsys.readouterr().out
    assert code == 0
    assert "firewall: DENY" in out
    assert "firewall: off" not in out


def test_cli_demo_without_firewall_only(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["demo", "--without-firewall", "--policy", str(POLICY_PATH)])

    out = capsys.readouterr().out
    assert code == 0
    assert "firewall: off" in out
    assert "firewall: DENY" not in out


def test_cli_demo_missing_policy_still_denies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["demo", "--with-firewall", "--policy", str(tmp_path / "missing.yaml")])

    out = capsys.readouterr().out
    assert code == 0
    assert "firewall: DENY (POLICY_UNLOADED)" in out
    assert "money moved: none" in out

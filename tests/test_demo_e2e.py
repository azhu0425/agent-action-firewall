"""Demo with the real engine and policy: the injected transfer is stopped (PLAN.md W3)."""

from __future__ import annotations

from pathlib import Path

from firewall.demo import run_demo
from firewall.engine import evaluate
from firewall.models import Decision, EvalRequest, Reason, Verdict
from firewall.policy import load_policy

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy" / "policy.yaml"


def test_demo_naive_agent_with_firewall_balance_unchanged() -> None:
    policy = load_policy(POLICY_PATH)

    result = run_demo(lambda request: evaluate(request, policy))

    assert result.tool == "transfer_funds"
    assert result.verdict is Verdict.DENY
    assert Reason.TAINTED_ARGUMENT in result.reasons
    assert result.balance_after_cents == result.balance_before_cents


def test_demo_naive_agent_without_firewall_loses_money_with_real_inbox() -> None:
    result = run_demo(None)

    assert result.balance_after_cents < result.balance_before_cents


def test_demo_benign_inbox_with_firewall_reads_summary() -> None:
    policy = load_policy(POLICY_PATH)
    seen: list[EvalRequest] = []

    def firewall(request: EvalRequest) -> Decision:
        seen.append(request)
        return evaluate(request, policy)

    result = run_demo(firewall, inbox=["Your September statement is ready."])

    assert result.tool == "get_account_summary"
    assert result.verdict is Verdict.ALLOW
    assert result.balance_after_cents == result.balance_before_cents
    assert len(seen) == 1

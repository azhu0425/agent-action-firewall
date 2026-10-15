"""Command-line interface: `replay`, `verify-audit` and `demo`.

Usage, from the repo root:
    python -m firewall.cli replay eval/corpus/attack.jsonl [--policy PATH]
    python -m firewall.cli verify-audit audit/audit.jsonl
    python -m firewall.cli demo [--with-firewall | --without-firewall] [--policy PATH]

Exit codes: 0 success, 1 a mismatch or a broken chain, 2 the input could not be loaded. Output
carries ids, verdicts, reason codes and hashes only, never argument values or message content
(AGENTS.md §2.2).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from firewall.audit import chain_head, verify_chain
from firewall.config import Settings
from firewall.demo import format_report, run_demo
from firewall.engine import evaluate
from firewall.errors import AuditError, PolicyError
from firewall.models import EvalRequest, Policy, Reason, Verdict
from firewall.policy import load_policy


class _Expected(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    decision: Verdict
    reasons: list[Reason]


class Trace(BaseModel):
    """One corpus-shaped row: {"id", "description", "request", "expected"}."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    id: str
    description: str = ""
    request: EvalRequest
    expected: _Expected


def _load_traces(path: Path) -> list[Trace]:
    """Raises OSError, ValueError (bad JSON) or ValidationError on unreadable or malformed rows."""
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    return [Trace.model_validate(json.loads(line)) for line in lines if line.strip()]


def _reasons(reasons: Sequence[Reason]) -> str:
    return ",".join(reasons) or "-"


def _replay(traces_path: Path, policy_path: Path) -> int:
    try:
        policy = load_policy(policy_path)
        traces = _load_traces(traces_path)
    except ValidationError as exc:
        # Pydantic errors can name client-chosen keys, so only the type is printed.
        print(f"LOAD ERROR {type(exc).__name__}", file=sys.stderr)
        return 2
    except (OSError, ValueError, PolicyError) as exc:
        # json.JSONDecodeError messages quote a position, never the document.
        print(f"LOAD ERROR {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if not traces:
        # "0/0 traces met expectations" would pass vacuously.
        print("LOAD ERROR no traces in file", file=sys.stderr)
        return 2
    print(f"{'id':<12} {'expected':<44} {'actual':<44} ok")
    mismatches = 0
    for trace in traces:
        decision = evaluate(trace.request, policy)
        # Same rule as the eval gate: verdict equal and every expected reason present.
        matched = decision.verdict == trace.expected.decision and set(
            trace.expected.reasons
        ) <= set(decision.reasons)
        mismatches += not matched
        expected = f"{trace.expected.decision} [{_reasons(trace.expected.reasons)}]"
        actual = f"{decision.verdict} [{_reasons(decision.reasons)}]"
        print(f"{trace.id:<12} {expected:<44} {actual:<44} {'ok' if matched else 'FAIL'}")
    print(f"\n{len(traces) - mismatches}/{len(traces)} traces met expectations")
    return 1 if mismatches else 0


def _verify_audit(log: Path) -> int:
    try:
        broken_at = verify_chain(log)
        if broken_at is not None:
            print(f"BROKEN at record {broken_at}")
            return 1
        count, head = chain_head(log)
    except AuditError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    print(f"OK {count} records, head {head}")
    return 0


def _demo(policy_path: Path, *, with_firewall: bool, without_firewall: bool) -> int:
    exit_code = 0
    if without_firewall:
        print("== without firewall ==")
        print(format_report(run_demo(None)))
    if with_firewall:
        policy: Policy | None
        try:
            policy = load_policy(policy_path)
        except PolicyError as exc:
            # Fail closed: the engine denies every call with POLICY_UNLOADED.
            # The demo still runs to show the DENY, but the exit code reports the load failure.
            print(f"WARNING {exc}", file=sys.stderr)
            policy = None
            exit_code = 2
        if without_firewall:
            print()
        print("== with firewall ==")
        print(format_report(run_demo(lambda request: evaluate(request, policy))))
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firewall.cli", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    replay = commands.add_parser("replay", help="replay JSONL traces and compare expectations")
    replay.add_argument("traces", type=Path)
    replay.add_argument("--policy", type=Path, default=None)

    audit = commands.add_parser("verify-audit", help="check the audit log's hash chain")
    audit.add_argument("log", type=Path)

    demo = commands.add_parser("demo", help="run the injected-email demo")
    which = demo.add_mutually_exclusive_group()
    which.add_argument("--with-firewall", action="store_true")
    which.add_argument("--without-firewall", action="store_true")
    demo.add_argument("--policy", type=Path, default=None)

    args = parser.parse_args(argv)
    if args.command == "verify-audit":
        return _verify_audit(args.log)
    policy_path: Path = args.policy or Settings().policy_path
    if args.command == "replay":
        return _replay(args.traces, policy_path)
    both = not (args.with_firewall or args.without_firewall)
    return _demo(
        policy_path,
        with_firewall=both or args.with_firewall,
        without_firewall=both or args.without_firewall,
    )


if __name__ == "__main__":
    sys.exit(main())

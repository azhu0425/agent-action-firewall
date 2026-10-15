#!/usr/bin/env python3
"""Single verification entry point: CI runs exactly this (AGENTS.md §3).

Usage: python scripts/verify.py [--strict]

Steps run in order and stop at the first failure. A declared step that is not enabled yet is
reported as SKIPPED. With --strict (CI from wave W3 on), any skip fails the run, so a gate can
never silently disappear.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

STEPS: dict[str, list[str]] = {
    "ruff-check": [PY, "-m", "ruff", "check", "."],
    "ruff-format": [PY, "-m", "ruff", "format", "--check", "."],
    "mypy": [PY, "-m", "mypy"],
    "pytest": [PY, "-m", "pytest", "--cov=firewall", "--cov-fail-under=80"],
    "hooks": [PY, "-m", "unittest", "discover", "-s", ".claude/hooks", "-p", "test_*.py"],
    "eval": [PY, "eval/run_eval.py", "--gate"],
    "mutation": [PY, "eval/run_eval.py", "--mutation"],
}

# Integrator-owned: changed only at wave boundaries (W0a, W3). See PLAN.md.
ENABLED_STEPS: list[str] = ["ruff-check", "ruff-format", "mypy", "pytest", "hooks"]


def run_steps(steps: Mapping[str, Sequence[str]], enabled: Sequence[str], strict: bool) -> int:
    """Run enabled steps in declaration order; return a process exit code."""
    unknown = sorted(set(enabled) - set(steps))
    if unknown:
        # A typo in ENABLED_STEPS must not quietly turn a gate into a skip.
        raise ValueError(f"enabled steps not declared in STEPS: {', '.join(unknown)}")
    results: list[tuple[str, str, float]] = []
    exit_code = 0
    for name, command in steps.items():
        if name not in enabled:
            results.append((name, "SKIPPED", 0.0))
            if strict:
                exit_code = exit_code or 2
            continue
        if exit_code:
            results.append((name, "NOT RUN", 0.0))
            continue
        print(f"==> {name}: {' '.join(command)}", flush=True)
        started = time.monotonic()
        returncode = subprocess.run(command, cwd=REPO_ROOT, check=False).returncode
        elapsed = time.monotonic() - started
        results.append((name, "PASS" if returncode == 0 else f"FAIL ({returncode})", elapsed))
        if returncode != 0:
            exit_code = 1

    print("\nverify summary")
    for name, status, elapsed in results:
        print(f"  {name:<12} {status:<10} {elapsed:6.1f}s")
    skipped = [name for name, status, _ in results if status == "SKIPPED"]
    if skipped:
        note = "failing (--strict)" if strict else "not yet enabled"
        print(f"  SKIPPED steps ({note}): {', '.join(skipped)}")
    print("RESULT:", "PASS" if exit_code == 0 else "FAIL")
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="fail if any step is skipped")
    args = parser.parse_args(argv)
    return run_steps(STEPS, ENABLED_STEPS, args.strict)


if __name__ == "__main__":
    sys.exit(main())

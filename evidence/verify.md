# Verification

## Checks and results

Results below were run on 2026-10-15 in the W4 worktree, with main (including W3, PR #14) merged in.

Source of the test count: the pytest summary line printed by `python scripts/verify.py --strict`.
On `fix/issue-16` (2026-10-15) it printed `395 passed, 1 warning` with total coverage 98.81%, and
all 7 steps passed. Only the tests row was updated from that run. The
main CI run before that branch, [38686019616](https://github.com/azhu0425/agent-action-firewall/actions/runs/38686019616)
at `19754ec`, printed `391 passed, 1 warning` in its `verify` job. Issue #16 added the four extra
tests.

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check .` | PASS |
| Format | `ruff format --check .` | PASS |
| Types | `mypy` (strict, `firewall/`) | PASS |
| Tests + coverage | `pytest --cov=firewall --cov-fail-under=80` | PASS: 395 tests, 98.81% total coverage (branch-enabled), re-run on `fix/issue-16`; see source below |
| Hook self-tests | `python -m unittest discover -s .claude/hooks` | PASS: 35 tests |
| Eval gate | `python eval/run_eval.py --gate` | PASS: 20 attack, 16 benign; attack block rate 1.0, benign false-deny rate 0.0, expectation match 1.0 |
| Mutation | `python eval/run_eval.py --mutation` | PASS: all 6 rules killed (removing any one lets an attack verdict get less severe) |
| Corpus integrity | `tests/test_eval_integrity.py` | PASS: every row parses, LF-normalised hashes match `eval/corpus.lock` |
| Static security | `uvx bandit==1.9.4 -r firewall eval` | PASS. Both `yaml.load` calls use a `SafeLoader` subclass and carry `# nosec B506` with the reason |
| Dependency CVEs | `uvx pip-audit==2.10.1` on `uv export --frozen --all-extras` | PASS: no known vulnerabilities |
| Single entry point | `python scripts/verify.py --strict` (what CI runs) | PASS: all 7 steps (ruff, format, mypy, pytest, hooks, eval, mutation), none skipped |
| Replay | `python -m firewall.cli replay` on the attack corpus | 20/20 traces met expectations (run by the integrator: the corpus path is guarded from agent shells) |
| Demo | `python -m firewall.cli demo` | Without the firewall $9,800.00 moves ($12,000.00 -> $2,200.00); with it DENY (AMOUNT_OVER_HARD_CAP, NEW_PAYEE, TAINTED_ARGUMENT) and the balance is unchanged |
| HTTP | `uvicorn firewall.api:app` and curl | `/health` 200 ok; headline request 200 DENY; `verify-audit` on the resulting log: OK, 1 record |

The first gate run against the human-written corpus matched 35 of 36 expectations; `ben-011`
exposed a wrong account-length bound in the rules, fixed test-first (`679eb6a` red, `3612694`).

## Local vs pull request vs pipeline

| Stage | What runs | Gate |
|---|---|---|
| Local, while coding | `python scripts/verify.py`, pre-commit (whitespace, YAML, private keys, ruff) | The agent may not claim "verified" without this run (AGENTS.md §4.6) |
| Local, agent guardrails | `protect_paths` hook, `require_plan_review` hook, permission deny list | Blocks writes to human-owned files and leaving plan mode unreviewed |
| Pull request | `ci.yml` job `verify` (`uv sync --locked`, `verify.py --strict`); `security.yml` (bandit, pip-audit, gitleaks, container build + `/health` smoke); `code-reviewer` subagent; Codex review; Claude review action when its secret is set | Ruleset on `main`: PR required, `verify` green, review threads resolved, squash merges only |
| After merge (`main`) | `ci.yml` and `security.yml` re-run on push | A red `main` is fixed forward or reverted |
| Release (W5) | Fresh clone, follow the README exactly, `gitleaks detect`, tag `v0.1.0` | Human says yes before the tag is pushed |

## Known gaps

- gitleaks runs only in CI. The Docker walkthrough (README Option A) was run locally on Docker
  Desktop 29.0.1 (Windows, Linux containers) and runs on every PR in the `container` CI job:
  compose up, strict verify inside the `verify` image, demo, the three example verdicts, audit
  chain, value-free logs, corpus replay, and fail-closed degraded mode.
- GitHub Actions and tool versions are pinned by tag, not by commit SHA. Dependabot is configured
  for security updates only. SHA pinning was deferred in the W0a review and is still open.
- The Claude PR-review action is skipped while `CLAUDE_CODE_OAUTH_TOKEN` is unset. The
  `code-reviewer` subagent and Codex stand in for it.
- The red-team pass (W4-A) and the README fresh-clone check (W3 checkpoint, W5) are later steps.
- Taint false negatives are documented, not tested away (DR-4).

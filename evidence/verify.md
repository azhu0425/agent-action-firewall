# Verification

## Checks and results

Results below were run on 2026-10-15 in the W4 worktree (main at PR #13, before W3 landed).

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check .` | PASS |
| Format | `ruff format --check .` | PASS |
| Types | `mypy` (strict, `firewall/`) | PASS |
| Tests + coverage | `pytest --cov=firewall --cov-fail-under=80` | PASS: 318 tests, 97% branch coverage |
| Hook self-tests | `python -m unittest discover -s .claude/hooks` | PASS: 35 tests |
| Eval gate | `python eval/run_eval.py --gate` | PASS: 20 attack, 16 benign; attack block rate 1.0, benign false-deny rate 0.0, expectation match 1.0 |
| Mutation | `python eval/run_eval.py --mutation` | PASS: all 6 rules killed (removing any one lets an attack verdict get less severe) |
| Corpus integrity | `tests/test_eval_integrity.py` | PASS: every row parses, LF-normalised hashes match `eval/corpus.lock` |
| Static security | `uvx bandit==1.9.4 -r firewall --skip B506` | PASS. Unskipped, bandit reports one B506 at `firewall/policy.py:54`, a false positive (a `SafeLoader` subclass); CI pairs the skip with a grep that fails on any other `yaml.load` |
| Dependency CVEs | `uvx pip-audit==2.10.1` on `uv export --frozen --all-extras` | PASS: no known vulnerabilities |
| Single entry point | `python scripts/verify.py` | PASS (ruff, format, mypy, pytest, hooks; eval and mutation SKIPPED until W3 enables them) |

<!-- TODO(W3): re-run `python scripts/verify.py --strict` after W3 enables eval and mutation, and
replace the test count, coverage and SKIPPED note above with that run's summary. -->

The first gate run against the human-written corpus matched 35 of 36 expectations; `ben-011`
exposed a wrong account-length bound in the rules, fixed test-first (`679eb6a` red, `3612694`).

## Local vs pull request vs pipeline

| Stage | What runs | Gate |
|---|---|---|
| Local, while coding | `python scripts/verify.py`, pre-commit (whitespace, YAML, private keys, ruff) | The agent may not claim "verified" without this run (AGENTS.md §4.6) |
| Local, agent guardrails | `protect_paths` hook, `require_plan_review` hook, permission deny list | Blocks writes to human-owned files and leaving plan mode unreviewed |
| Pull request | `ci.yml` job `verify` (`uv sync --locked`, `verify.py`); `security.yml` (bandit, pip-audit, gitleaks, container build + `/health` smoke); `code-reviewer` subagent; Codex review; Claude review action when its secret is set | Ruleset on `main`: PR required, `verify` green, review threads resolved, merge commits only |
| After merge (`main`) | `ci.yml` and `security.yml` re-run on push | A red `main` is fixed forward or reverted |
| Release (W5) | Fresh clone, follow the README exactly, `gitleaks detect`, tag `v0.1.0` | Human says yes before the tag is pushed |

## Known gaps

- `scripts/verify.py` does not yet run the eval and mutation steps (W3 enables them and switches CI
  to `--strict`).
- The `container` job in `security.yml` cannot pass until `firewall/api.py` lands in W3.
- The Docker build and gitleaks were not run locally (Docker daemon not running on the authoring
  machine); their first real run is in CI.
- GitHub Actions and tool versions are pinned by tag, not by commit SHA. Dependabot is configured
  for security updates only. SHA pinning was deferred in the W0a review and is still open.
- The Claude PR-review action is skipped while `CLAUDE_CODE_OAUTH_TOKEN` is unset. The
  `code-reviewer` subagent and Codex stand in for it.
- The red-team pass (W4-A) and the README fresh-clone check (W3 checkpoint, W5) are later steps.
- Taint false negatives are documented, not tested away (DR-4).

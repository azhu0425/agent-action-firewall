# Agentic workflow

## Tools and agents
## Decomposition (waves and streams)
## Representative steering prompts
## Intervention log

| Stream | Prompt (short) | Agent output | What was wrong | How caught | Fix | Commit |
|---|---|---|---|---|---|---|
| Setup | Guard hook written by agent | `protect_paths` hook | It blocked the agent's own read-only validation command, because the command named `.claude/settings.json` | Hook denial at runtime | Kept the hook strict and changed the validation to avoid naming protected paths. The trade-off is documented | bootstrap |
| W0a | "Format the codebase" | `ruff format` over the whole repo | It would have reformatted the human-owned hook files | Hook denial | Scoped `ruff format` away from the hook directory in `pyproject.toml`. The human owns those files | W0a green |
| W0a | Contract freeze | `models.py` and stubs from the integrator agent | Self-review found fail-open gaps: NaN/Infinity amounts and caps slip past comparisons; agent-chosen tool and argument names could inject log lines; empty `taint_fields` silently disabled taint; an untrusted `known_payees` would defeat NEW_PAYEE; the signature test would break once rules landed | `code-reviewer` subagent (fresh context) before merge | Added 19 red regression tests, then fixed the contract: `allow_inf_nan=False`, identifier patterns, size caps, Decision invariants, `INVALID_ARGUMENT`, DR-1 trust boundary | `6d6a49d` (red) and the fix commit |
| W0a | Same contract | `_Strict` base model | Pydantic `ValidationError` text echoes the submitted value, so logging a validation failure would leak account details. Claude's own self-review **missed** this | **Codex** PR review (cross-vendor), P0 | Red test, then `hide_input_in_errors=True` on the base model | W0a P0 fix |

| W2 | Synthetic data rule (§2.3) | Headline story, docs, tests and corpus drafts by several agents | `062-000` is a **real CBA branch BSB**, and the drafts also used real-looking 633/732/802 prefixes. Every Claude agent, including the corpus author and all reviewers, missed this | **Codex** PR review on #8 (cross-vendor) | Every BSB replaced with the `000` prefix across main, the open branches and the corpus drafts. §2.3 now names the allowed prefix | fix/synthetic-bsbs |

## Plan and code review findings
## Solution selection
See `docs/design-history/2026-10-15-solution-selection.md`.

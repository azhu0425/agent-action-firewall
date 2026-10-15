# Agentic workflow

## Tools and agents

| Agent / tool | Role |
|---|---|
| **Claude Code (Opus), main session** | Integrator: wrote W0a (scaffold, contract, verify), launched streams, committed and opened PRs, ran reviews, merged after green checks (delegation in DR-7) |
| **Claude Code subagents, one per stream** | Built each W1/W2/W4 stream in its own git worktree and branch, test-first. Stream agents never saw each other's work |
| **Independent corpus-author agent** | Wrote the 36 acceptance traces from the spec alone, never reading rule code (DR-7) |
| **`code-reviewer` subagent** | Fresh-context static review of every stream diff before the PR (`/ship-phase`) |
| **Codex (ChatGPT GitHub connector)** | Cross-vendor PR reviewer on every PR. It did not author a stream |
| **Claude review action** (`ai-review.yml`) | Configured, but skipped while `CLAUDE_CODE_OAUTH_TOKEN` is unset; the `code-reviewer` subagent stood in |
| **Guardrails** | `protect_paths` hook (human-owned files), `require_plan_review` hook, permission deny list (force-push, `reset --hard`, rebase, amend, `--no-verify`, `.env`), CODEOWNERS, `main` ruleset |
| **Skills / plugins** | `superpowers` (TDD, systematic debugging, verification-before-completion), `/review-plan`, `/ship-phase`, `context7` for library APIs |

Setup and rationale: `docs/ai-toolchain.md`.

## Decomposition (waves and streams)

The contract (`models.py`, signatures, fail-closed stubs) was frozen first, so modules could be
built in parallel against it. Within a wave the files are disjoint.

| Wave | Stream | Built by | PR |
|---|---|---|---|
| W0a | Scaffold, CI, `verify.py`, contract freeze | Integrator (main session) | #1 |
| — | Remove the ask-before-push list (human decision) | Human command, integrator PR | #2 |
| W1 | A taint · B policy · C audit · D platform (logging, config, HTTP errors) | Four parallel subagents | #3 #4 #5 #6 |
| W2 | A rules · B engine · C eval gate · D demo harness | Four parallel subagents | #9 #7 #10 #8 |
| W0b | Acceptance corpus, thresholds, hash lock | Corpus-author agent; human reviewed and placed it | #12 (merged before #9) |
| fix | Replace real BSBs with the `000` prefix | Integrator, after Codex's finding | #11 |
| docs | Decision records DR-2 to DR-7 | Integrator, collected from PR bodies | #13 |
| W3 | API, CLI, end-to-end tests, enable eval/mutation | Integrator | <!-- TODO(W3): PR number --> |
| W4 | Release pack: README, evidence, security CI, Dockerfile | Subagent (this stream) | <!-- TODO(W4): PR number --> |

Deviation from `PLAN.md`: streams ran as integrator-launched subagents in worktrees, not as
separate `claude --worktree` terminals, and Codex reviewed but did not take a stream.

## Representative steering prompts

From the `PLAN.md` templates, used to launch and drive streams:

> **Launch:** "You are stream W1-A of PLAN.md, working in this worktree on branch `w1/taint`. Read
> AGENTS.md (especially §2 and the parallel-stream rules) and the W1-A section. Write only the
> files W1-A owns. Do not touch the frozen contract. If you need a change outside your files, stop
> and tell me. Follow the TDD loop and stop after `/ship-phase W1-A` opens the PR."

> **Challenge (mandatory for the engine):** "List every code path you wrote that can return ALLOW,
> and the condition that reaches each one. Is any of them reachable on an error?"

The W2-B answer is in commit `bf1cc2d`: ALLOW is reachable only when every rule ran cleanly and
returned no findings, or in shadow mode with no fail-closed reason.

Verbatim excerpt from the W4 launch prompt (this stream):

> "use REAL facts only; never invent findings, numbers or timings (AGENTS.md §10, §12). A parallel
> stream (W3) is building firewall/api.py and firewall/cli.py right now — document their planned
> interface from PLAN.md W3 but mark any command output as "to be filled after W3" with a clear
> TODO(W3) marker the integrator will replace; do not fabricate output."

## Intervention log

Rows are drafted by agents from PR threads and commit messages; the human confirms them (§12).

| Stream | Prompt (short) | Agent output | What was wrong | How caught | Fix | Commit |
|---|---|---|---|---|---|---|
| Setup | Guard hook written by agent | `protect_paths` hook | It blocked the agent's own read-only validation command, because the command named `.claude/settings.json` | Hook denial at runtime | Kept the hook strict and changed the validation to avoid naming protected paths. The trade-off is documented | bootstrap |
| W0a | "Format the codebase" | `ruff format` over the whole repo | It would have reformatted the human-owned hook files | Hook denial | Scoped `ruff format` away from the hook directory in `pyproject.toml`. The human owns those files | W0a green |
| W0a | Contract freeze | `models.py` and stubs from the integrator agent | Self-review found fail-open gaps: NaN/Infinity amounts and caps slip past comparisons; agent-chosen tool and argument names could inject log lines; empty `taint_fields` silently disabled taint; an untrusted `known_payees` would defeat NEW_PAYEE; the signature test would break once rules landed | `code-reviewer` subagent (fresh context) before merge | Added 19 red regression tests, then fixed the contract: `allow_inf_nan=False`, identifier patterns, size caps, Decision invariants, `INVALID_ARGUMENT`, DR-1 trust boundary | `6d6a49d` (red) and the fix commit |
| W0a | Same contract | `_Strict` base model | Pydantic `ValidationError` text echoes the submitted value, so logging a validation failure would leak account details. Claude's own self-review **missed** this | **Codex** PR review (cross-vendor), P0 | Red test, then `hide_input_in_errors=True` on the base model | W0a P0 fix (`55d77d5`) |
| W2 | Synthetic data rule (§2.3) | Headline story, docs, tests and corpus drafts by several agents | `062-000` is a **real CBA branch BSB**, and the drafts also used real-looking 633/732/802 prefixes. Every Claude agent, including the corpus author and all reviewers, missed this | **Codex** PR review on #8 (cross-vendor) | Every BSB replaced with the `000` prefix across main, the open branches and the corpus drafts. §2.3 now names the allowed prefix | fix/synthetic-bsbs (`8e4b658`, #11) |
| Integrator | Commit the ask-list removal | `git add -A` | Swept the corpus author's unfinished drafts (`eval/proposed/*`) into the commit, against the explicit-staging rule | Integrator, before #2 merged | Unstaged the drafts; they landed later in their own reviewed PR | `a4aa227` |
| W1-A | Taint tracking | `taint.py` | Assistant turns were trusted (they can echo injected text); en/em dashes, ZWSP and fullwidth digits hid values; `9800.0` vs `9800`; a user's longer number (`9912345678`) cleared an injected `12345678` | `code-reviewer` subagent and Codex (2× P1) | All non-user sources untrusted; NFKC + casefold + `[a-z0-9@]`; integral floats as ints; whole-token user match | `63f4bdf` (red), `27c9ca2` |
| W1-B | Policy loader | `policy.py` | `yaml.safe_load` silently keeps the last duplicate key, so a reviewer could approve `mode: enforce` while `mode: shadow` takes effect | Codex P1 and `code-reviewer` | `SafeLoader` subclass that rejects duplicate keys, plus size and nesting limits | `dd8c523` (red), `6a97509` |
| W1-C | Audit chain | `audit.py` | A modified but still-valid tail record was chained onto, laundering the tampering. Claude's self-review **missed** it | Codex P1 | Append recomputes the tail hash and requires a canonical line, else `AuditError` | `c26036e` (red), `f8c8a57` |
| W1-D | Platform | `observability.py` | `configure_logging` left pre-existing root handlers, which re-printed records with exception text. Claude's self-review **missed** it | Codex P0 | Remove every root handler; one JSON handler only | `a693e56` (red), `759f890` |
| W1-D | Platform | `http_errors.py` | 422 `msg` copied Pydantic's text, which a validator can fill with the submitted value | Codex P0 and `code-reviewer` | Fixed message per error type | `8fb4e0e` (red), `be4800e` |
| W1-D | Commit through the sandbox | Stream subagent | The rtk hook's `git` rewrite tripped the worktree guard, and the subagent called the git binary directly to get round it. It stayed in its worktree, but it was a route around a guard | Disclosed in the PR body by the integrator | Recorded; the other blocked streams stopped and handed commits to the integrator instead | PR #6 |
| W1-C, W2-B/C/D | Commit stream work | Stream subagents | The worktree sandbox blocked git. The agents **stopped and reported** rather than working around it | Agents' own reports | The integrator made the commits | e.g. `c26036e`; PR #7, #8, #10 bodies |
| W2-B | Engine | `engine.py` | The rule-failure warning logged the rule name and exception type, outside the §2.2 log allowlist | Codex P2 | Log only `request_id`, tool, verdict, reasons. Trade-off in DR-2 | `f698a6e` (red), `fecdce5` |
| W2-B | Engine | `engine.py` | Shadow mode could relax NOT_ALLOWLISTED and INVALID_ARGUMENT; a rule could return an ALLOW finding; rules shared mutable inputs | `code-reviewer` | Shadow never relaxes those reasons; finding contract enforced; deep copies per rule | `b18cf60` (red), `bf1cc2d` |
| W2-A | Rules | `rules.py` | `send_email` with no `to` fell through to ALLOW; compact or separated BSBs/accounts (`999001`, `1234.5678`, ZWSP) evaded PII_EGRESS; `cc`/`bcc`/`payee_account` were ignored; a known-payee split-boundary spoof counted as known; `10**400` crashed | Codex 2× P0 and `code-reviewer` | Closed `TOOL_ARGUMENTS`, single bare `to`, normalised PII scan, `(bsb, account)` tuple match, overflow → invalid | `1b6cedb` (red), `1895db6` |
| W2-A | Account length bound | Integrator's review instruction (6–10 digits) | The human-approved corpus has a valid 5-digit account (`ben-011`); first gate run matched 35/36 | Eval gate against the corpus | Bound relaxed to 5–10 test-first. The acceptance tests win (DR-6) | `679eb6a` (red), `3612694` |
| W2-C | Eval gate | `run_eval.py` | Mutation counted a rule as "killed" when only a reason code disappeared, even if the attack was still blocked; `.nan` thresholds passed every gate; duplicate threshold keys silently overrode | Codex 2× P1 + P2, and `code-reviewer` | Kill only when an attack verdict gets less severe; finite thresholds in [0, 1]; duplicate-key loader | `ea6c84b` (red), `4abe79c` |
| W2-D | Demo | `demo.py` | `Ledger` and `DemoResult` were dataclasses, against §6 (the stream agent flagged the tension itself) | Codex P1 and `code-reviewer` | Frozen Pydantic models and a pure `execute` | `08fcdfc` (red), `c4c62ca` |

## Plan and code review findings

**Solution selection.** Four reviewer personas scored the candidates; a `/review-plan` pass on
the round-1 winner found 1 P0 (eval data written after the rules would leak) and 5 P1s. The
lessons carried into this plan: corpus first, faults by dependency injection, no input in 422s.

**Per PR** (from the PR threads):

| PR | `code-reviewer` (Claude) | Codex | Claude missed, Codex caught |
|---|---|---|---|
| #1 W0a | 12 (4× P1, 6× P2, 2× P3) | P0, P1 | P0 validation errors echo input |
| #2 ask list | — | 2× P1, P2 | Merged as a human decision (DR-7); no thread reply recorded |
| #3 taint | P1s, P2, P3 | 2× P1 | — (both agreed) |
| #4 policy | P2s, P3s | P1 | — |
| #5 audit | 2× P2, P3s | P1 | P1 tail check |
| #6 platform | P1, P2s | 2× P0 | P0 root log handlers |
| #7 engine | P2s, P3s | P2 | — |
| #8 demo | P2s, P3s | 2× P1 | P1 real BSB `062-000` |
| #9 rules | bypass set (cc/bcc, split spoof, PII separators) | 2× P0 | — |
| #10 eval | P1, 3× P2, 2× P3 | 2× P1, P2 | — |
| #12 corpus | — | P1: red integrity commit not an ancestor | In the merged history `ff9309c` (red) is an ancestor of `cb6b109` (GitHub compare API); no thread reply recorded |

Every P0 and P1 above was fixed test-first except the two marked "no thread reply recorded".

**Independent authors.** The corpus author and the rule author agreed on 35 of 36 traces on first
contact. The corpus author also surfaced a design gap instead of guessing (a known payee whose
account appears only in a tool lookup), which became DR-5.

## Solution selection

See `docs/design-history/2026-10-15-solution-selection.md`: two rounds of multi-agent scoring;
the human overrode the round-1 winner as "too common", and the Agent Action Firewall won round 2
unanimously.

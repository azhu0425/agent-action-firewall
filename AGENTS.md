# AGENTS.md

Operating rules for every coding agent working in this repository (Claude Code, Codex, Cursor,
GitHub Copilot, Gemini CLI, Windsurf, Amp, Aider, Cline, Junie, …) and for the humans directing
them. This file is the **single source of truth**. Tool-specific files (`CLAUDE.md`, `GEMINI.md`,
`.cursor/rules/`, `.github/copilot-instructions.md`, …) only point here, so the rules cannot drift.

Precedence: a direct instruction from the human in the current session beats this file, **except
the invariants in §2**, which change only through a human-reviewed PR to this file. A more specific
`AGENTS.md` in a subdirectory overrides this one for that subtree.

---

## 1. Project

**Agent Action Firewall.** A bank deploys LLM agents (a customer assistant, a support agent) that
propose tool calls such as `transfer_funds` or `send_email`. The firewall sits between the agent
and the tools. It evaluates each proposed call plus its session context, where every message is
tagged with its `source`. It returns `ALLOW`, `DENY` or `REQUIRE_HUMAN_APPROVAL` with reason codes.
It fails closed, traces argument provenance to catch prompt injection, and writes a hash-chained
audit log. The core path has no LLM, no network and no paid keys: it replays synthetic agent traces.

Built as an AI-agent-driven engineering exercise. **How the AI was used is assessed as much as the
code.** Treat process evidence (§12) as a deliverable.

| Source of truth | Holds |
|---|---|
| `PLAN.md` | Waves and streams, file ownership, red tests per stream, cut-lines |
| `evidence/design.md` | Architecture, data flow, request/response contract, reason codes |
| `evidence/decisions.md` | Decision records. Read before re-litigating a choice |
| `policy/policy.yaml` | Firewall policy (code-reviewed config) |
| `eval/corpus/*.jsonl` | Human-written attack/benign traces = acceptance tests (**read-only for agents**) |
| `docs/ai-toolchain.md` | How the AI tooling is set up and why |

Verify against the current code, not against prose. If behaviour changes, update the doc that
describes it in the same PR.

## 2. Invariants (never break; if a task seems to need it, stop and ask)

1. **Fail closed.** Any exception, unknown tool, missing/invalid policy or unparseable input
   gives `DENY`, never `ALLOW`. Do not add a default, fallback or `except` branch that allows.
2. **No argument values, message content or PII in logs, errors or exception messages.** Log
   request id, tool name, decision, reason codes and latency only.
3. **Synthetic data only.** Phone numbers from the ACMA fictional ranges (`0491 570 xxx`,
   `02 5550 xxxx`). Domains from RFC 2606 (`example.com`, `*.test`). Luhn-invalid card numbers.
   Made-up BSBs. No real people, customers, staff or Westpac data.
4. **Human-owned files are read-only for agents.** These are listed in
   `.claude/protected-paths.txt`: the eval corpus, its hash lock, thresholds and the agent
   guardrails themselves. Three layers enforce this: a Claude Code hook, `CODEOWNERS` review and
   a corpus-integrity test in CI.
5. **Offline core path.** No network calls, no LLM, no paid API keys in anything `verify` or the
   README run path executes.
6. **No new runtime dependency** without a decision record in `evidence/decisions.md`.
7. **Never weaken, skip, xfail or delete a test to get green.** Changing an existing assertion
   needs a "why" in the PR description.

## 3. Commands

Run from the repo root. They work in PowerShell, Git Bash and CI. These exist from wave W0a onward.

| Task | Command |
|---|---|
| Setup (uv) | `uv sync --all-extras` |
| Setup (no uv) | `python -m venv .venv` → activate → `pip install -e ".[dev]"` |
| **Verify (what CI runs)** | `python scripts/verify.py` |
| One test file / test | `python -m pytest tests/test_rules.py -q` / `-k name` |
| Run API | `uvicorn firewall.api:app --reload` |
| Replay traces | `python -m firewall.cli replay eval/corpus/attack.jsonl` |
| Check audit chain | `python -m firewall.cli verify-audit <log>` |
| Hook self-test | `python -m unittest discover -s .claude/hooks -p "test_*.py"` |

`scripts/verify.py` is the single entry point. CI calls it, and `verify.ps1`/`verify.sh` are thin
wrappers around it. Do not hand-roll a different check sequence and call it "verified".

## 4. Workflow: one PLAN.md stream = one worktree = one branch = one PR

1. **Orient.** Read your stream in `PLAN.md`, the code it touches, and §2.
2. **Plan.** For anything beyond a one-file change, plan first (Claude Code: plan mode). The plan
   gets a multi-agent review (`/review-plan`) before it is accepted. In Claude Code a hook
   enforces this.
3. **Red.** Write your stream's listed failing tests. Run them and confirm they fail **for the
   expected reason** (an assertion, not a typo or import error). Commit:
   `test(<scope>): <behaviour> [red]`.
4. **Green.** Write the minimal implementation that passes. Do not edit the red tests to fit the
   code. Commit: `feat(<scope>): …`.
5. **Refactor** with the tests green. Commit separately if non-trivial.
6. **Verify.** Run `python scripts/verify.py` and get exit 0. Never claim a check passed unless you
   ran it in this session and saw the result.
7. **Self-review.** A fresh-context reviewer (the `code-reviewer` subagent, or a second agent)
   reviews `git diff origin/main...HEAD`. Fix every P0/P1 finding before pushing.
8. **PR.** Push the branch and open a PR using the template. CI and AI review run. A human merges.
9. **Evidence.** Draft intervention-log rows (§12) for anything the human corrected.

### Parallel streams (`PLAN.md` waves)

Work is split into waves of streams that run concurrently, at most 4 at a time. When you are
assigned a stream:

- **Location.** Work only in your own worktree and on your own branch, `w<n>/<stream>`.
- **Your files.** Write only the files `PLAN.md` lists for your stream. If you need a change
  anywhere else, **stop and report it**. Never make the edit "just this once".
- **The frozen contract.** Never change `firewall/models.py`, `firewall/errors.py` or any signature
  covered by `test_contract_signatures_match`. Contract changes go through a `contract:` PR from
  the integrator.
- **Integrator-owned files.** Never edit `pyproject.toml`, `uv.lock`, `scripts/verify.py`,
  `tests/conftest.py`, `firewall/__init__.py` or `evidence/decisions.md`. Put any decision
  records in your PR body.
- **Other streams.** Never merge, rebase or cherry-pick another stream's branch. To pick up
  merged work, run `git merge main`.
- **Stubs.** Each stub stays fail-closed until its stream replaces it. Never weaken a stub so that
  your tests pass.

Explore before editing. Keep diffs focused on your stream. Never touch unrelated files. The working
tree may be dirty: preserve changes you did not make. Diagnose with evidence (a failing test,
logs, real output) before fixing. A guess is not a diagnosis.

## 5. Test-driven development rules

- Tests come from the acceptance list in `PLAN.md` and the failure-mode table in
  `evidence/design.md`, not from the implementation.
- **Failure paths are first-class.** Every row of the failure-mode table has a test.
- One behaviour per test, named `test_<unit>_<condition>_<expected>`. Use Arrange/Act/Assert with
  no logic in tests.
- Inject faults through dependency injection (function parameters or FastAPI
  `dependency_overrides`). Never use an env flag in the production path, and never monkeypatch the
  unit under test.
- Tests are deterministic: no network, no sleeps, no wall-clock races, seeded randomness.
- The eval corpus is the acceptance suite. Gate on it, never tune it: it is human-owned.
- Coverage (≥80%) is a floor, not a goal. The mutation check (disable each rule, and an attack
  must get through) proves that each rule carries weight.

## 6. Code conventions

- Python 3.12, FastAPI, Pydantic v2 (all external input is parsed into a model at the boundary),
  pydantic-settings for config, validated at startup.
- **Types.** Fully annotate public functions and let inference handle locals. Import types from
  libraries and never redeclare them. `mypy --strict` must pass on `firewall/`.
- **Style.** `ruff check` and `ruff format`, line length 100. No unused code, no wildcard imports.
- **Shape.** Rules and the engine are pure functions: `(call, context, policy) -> findings`. No
  classes except Pydantic models and framework objects. No global mutable state.
- **Errors.** Raise specific exceptions. Never use a bare `except`, and never swallow an error.
  The only broad `except Exception` is at the engine's fail-closed boundary, and it converts the
  error to `DENY EVALUATOR_ERROR`.
- **Logging.** Use `logging.getLogger(__name__)` and the JSON formatter from
  `firewall/observability.py`, with a `request_id` on every line. Never use `print` in library
  code.
- **Simplicity.** YAGNI. Prefer the stdlib. No speculative abstractions, plugin systems or
  "future" parameters. No placeholders (`...`, `pass  # TODO`, "rest of code here").

## 7. Comments and docs: what is useful, what is noise

Comments are for the reviewer six months from now. **Explain why. The code already says what.**

| Write | Don't write |
|---|---|
| Why a non-obvious choice was made, with a link: `# Most-restrictive-wins: see decisions.md#DR-2` | A restatement of the code: `# increment counter` |
| Invariants and security constraints: `# Fail closed: an evaluator error must never ALLOW` | Step narration: `# loop over the rules` |
| Format or unit assumptions: `# amounts are integer cents` | Change history: `# fixed bug`, `# new`, `# updated to use X` |
| Known limitations: `# taint is lexical; paraphrase evades it (decisions.md#DR-4)` | AI artefacts: `# Here is the updated function`, apologies, praise |
| Regex intent with an example: `# BSB: 062-000 or 062000` | Commented-out code (git remembers it) |
| `TODO(#12): …` linked to an issue | A bare `TODO`/`FIXME` |

- Write docstrings on public modules and functions **when the contract is not obvious from the
  name and types**: what it guarantees and how it fails. Don't write docstrings that repeat the
  signature.
- Define each reason code once, in `firewall/models.py`, with a one-line meaning. Don't duplicate
  it in comments.
- Never leave a comment that disagrees with the code. Fix one or the other in the same commit.

## 8. Git, commits and pull requests

- `main` is protected. Work on `w<n>/<stream>` (a `PLAN.md` stream) or `fix/<slug>`. No direct pushes after the
  bootstrap commit.
- **Commits** follow Conventional Commits: `type(scope): imperative subject` of 72 characters or
  fewer. The body says *why* and what was verified. Keep red and green commits separate. Commits
  with substantial AI-generated content carry a `Co-authored-by:` trailer for the agent, so the
  AI contribution can be audited from `git log`.
- **Merging** uses a merge commit only: `gh pr merge <n> --merge --delete-branch`. **Never squash
  or rebase-merge.** The exercise brief requires the incremental history to stay intact. Never
  force-push, amend or rebase pushed commits, rewrite history, or use `--no-verify`.
- **PR size.** One stream, ideally under 400 changed lines (excluding lockfiles and data). Split it
  if bigger.
- **PR description.** Follow `.github/pull_request_template.md`: Why, What, How verified (commands
  and results), AI usage (which agent, what it generated, what the human changed), Risk and
  rollback.
- **Review severities.** P0 means fail-open, a security hole or data exposure. P1 means
  incorrect behaviour. Both are **fixed** before merge. P2 is fixed or answered with a reason. P3
  is optional. Every AI review comment gets a reply.
- **Cross-vendor review.** Code written by one model family is also reviewed by another (for
  example Claude writes and Codex reviews) to reduce correlated blind spots.

## 9. Security and configuration

- The core path needs no secrets. Config comes from env vars validated by pydantic-settings.
  `.env.example` documents each variable, and `.env` is gitignored and never read by agents.
- Error responses are generic and carry a `request_id`: no stack traces, no echoed input (the
  custom 422 handler strips `input`).
- Dependencies are pinned by the lockfile. `pip-audit`, `bandit` and `gitleaks` run in CI.
- Policy changes are code changes: they go through a PR, the policy-diff CI job replays both
  corpora, and rollback means reverting the commit.

## 10. Agents must not

- Push to `main`, merge PRs, create or delete repositories, change repository settings or add
  secrets. These are human actions; agents may prepare the exact command.
- Write to protected paths, or modify or disable hooks, permission settings or CI gates in order
  to get past them.
- Run destructive git commands (`reset --hard`, `clean -fdx`, `push --force`, `branch -D` on
  unmerged work) or install global tools.
- Add dependencies silently or reach the network from the core path.
- Fabricate anything: test output, coverage, review findings, timings or evidence entries.

## 11. Definition of done (per stream)

- [ ] The stream's red tests were committed before the implementation, and are now green
- [ ] `python scripts/verify.py` exits 0 locally, and CI is green on the PR
- [ ] The self-review ran and every P0/P1 is fixed. The AI PR review comments are answered
- [ ] Docs touched by the behaviour change are updated (README, `evidence/*`)
- [ ] Intervention-log rows are drafted and confirmed by the human

## 12. Evidence capture

The panel assesses *how* agents were used. Capture it as you go, not at the end.

- `evidence/agentic-workflow.md` keeps an **intervention log**. When the human rejects, corrects
  or overrides agent output, the agent drafts a row: stream, prompt (short), what the agent
  produced, what was wrong, how it was caught (test, review, human read), the fix, and the commit
  SHA. The human confirms or edits it. Never invent or embellish an entry.
- Keep 1–2 representative steering prompts per stream, verbatim, and which agent (Claude, Codex, …) ran each stream.
- Record real plan-review and code-review findings and their dispositions. The solution-selection
  process is already recorded in `docs/design-history/`.

## 13. AI toolchain

**Repo-enforced** (anyone who clones this repo gets these):

- `.claude/settings.json`: permission posture (`acceptEdits`, deny for destructive git and `.env`;
  the human removed the ask-before-push/merge list to delegate those to the integrator agent) and hooks. The project settings take precedence over a
  developer's personal settings.
- Hooks: `protect_paths.py` (human-owned files) and `require_plan_review.py` (no leaving plan mode
  without `/review-plan`). Each has its own tests.
- Commands: `/review-plan` (parallel architect, gatekeeper and test reviewers) and
  `/ship-phase <stream-id>` (verify, self-review, PR, CI, AI review, then hand back to the human).
- Subagents: `code-reviewer` (static pre-PR review) and `red-team-reviewer` (tries to bypass the
  firewall).
- CI: `ci.yml` (verify and security checks) and `ai-review.yml` (a Claude PR review against this
  file). The Codex GitHub reviewer is the cross-vendor second opinion.
- Plugin: `superpowers` (process skills below).

**Which skill to use, and when (Claude Code):**

| Situation | Use |
|---|---|
| New feature or design question | `superpowers:brainstorming`, then plan mode |
| Multi-step work | `superpowers:writing-plans`, then `/review-plan` |
| Implementing | `superpowers:test-driven-development`; `superpowers:subagent-driven-development` for independent tasks |
| Failing test or bug | `superpowers:systematic-debugging`. No guessing |
| About to say "done" | `superpowers:verification-before-completion` |
| Before opening a PR | `code-reviewer` subagent / `superpowers:requesting-code-review` |
| Handling review comments | `superpowers:receiving-code-review`. Verify each claim; don't comply performatively |
| Library or API usage | `context7` docs lookup. Don't guess signatures |
| UI work (stretch only) | `frontend-design`, `design-taste-frontend`, `impeccable` |

Personal tooling (RTK, caveman, usage-guard, Obsidian memory) is optional and never required by
the repo. `docs/ai-toolchain.md` has the full setup, the reasoning, and the practices carried over
from earlier production work.

**Other agents:** Codex, Amp, Jules, Cursor, Copilot (coding agent), Windsurf, Junie, opencode,
Zed and Devin read this file natively. Pointer files cover Claude Code, Gemini CLI, Cursor rules,
Copilot Chat, Windsurf, Cline and Aider, and `tests/test_agent_instructions.py` fails if a pointer
stops referencing this file. To change agent behaviour, **edit this file only**.

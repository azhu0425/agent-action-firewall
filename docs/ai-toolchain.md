# AI toolchain and practices

This explains how this repository is set up for AI-assisted development and why. Agents get the
operational rules from `AGENTS.md`. This file is for humans: setup steps, rationale, and where each
practice came from.

## 1. Principles

1. **One source of truth for agent rules.** `AGENTS.md` holds the rules. Every tool-specific file
   only points to it, and a test fails if a pointer drifts. This lesson came from maintaining a
   35 KB `CLAUDE.md` in a production codebase: rules duplicated across files diverge.
2. **Gates for everyone live in git hooks and CI, not in one agent's config.** Claude Code hooks
   are for agent-specific guardrails. Quality gates (`verify`, ruff, gitleaks) run in pre-commit
   and CI, so they apply to Codex, Cursor and humans too.
3. **Defence in depth for anything that matters.** Human-owned eval data is guarded by an agent
   hook, CODEOWNERS review and a hash test in CI. Any single layer can be bypassed; all three
   together are hard to get past.
4. **Humans own intent and acceptance. Agents own implementation.** The human writes the eval
   corpus, thresholds and contract. Agents write tests from them and then the code.
5. **Every claim is verified.** "Tests pass" means the command ran in this session and exited 0.
   The panel can check this in CI logs.
6. **A different model reviews.** Claude writes the code, and the Codex GitHub reviewer reviews
   alongside a Claude review action. Models from the same family share blind spots.

## 2. Repo-enforced tooling (anyone who clones gets it)

| Piece | Where | What it does |
|---|---|---|
| Agent rules | `AGENTS.md` + pointers | Invariants, TDD loop, comment rules, PR conventions |
| Permission posture | `.claude/settings.json` | `acceptEdits`; denies force-push, `reset --hard`, rebase, amend, `--no-verify`, `.env` reads. Project settings override a developer's personal mode (including `bypassPermissions`) |
| Path guard hook | `.claude/hooks/protect_paths.py` | Fail-closed block on agent writes to `.claude/protected-paths.txt` entries. Has its own tests |
| Plan review hook | `.claude/hooks/require_plan_review.py` | Can't leave plan mode until `/review-plan` has run. Has its own tests |
| `/review-plan` | `.claude/commands/` | Parallel architect, gatekeeper and test reviewers with P0–P2 findings |
| `/ship-phase <stream-id>` | `.claude/commands/` | verify → `code-reviewer` → PR → CI → AI review → hand-back for merge |
| `code-reviewer` | `.claude/agents/` | Static, read-only diff review with severity, file:line and fix |
| `red-team-reviewer` | `.claude/agents/` | Tries to bypass the firewall and finds fail-open paths |
| Pre-commit | `.pre-commit-config.yaml` | Whitespace/EOF/YAML/large-file/private-key checks and ruff (corpus excluded from fixers) |
| CI | `.github/workflows/ci.yml` | `python scripts/verify.py` on every PR and on pushes to `main` |
| AI PR review | `.github/workflows/ai-review.yml` | Claude reviews each PR against `AGENTS.md` and posts inline P0–P3 comments |
| Ownership | `.github/CODEOWNERS` | Human review required for the corpus, policy, CI and agent config |
| PR template | `.github/pull_request_template.md` | Why / What / How verified / AI usage / Risk |
| Plugin | `superpowers` (enabled in project settings) | Brainstorming, writing-plans, TDD, systematic-debugging, verification-before-completion, code-review skills |

## 3. Personal toolchain (author's setup, optional)

These are not required to work in the repo. They are listed so the workflow is reproducible and
discussable.

- **Claude Code** (Opus, extended thinking, high effort) is the primary agent. Global hooks:
  - SessionStart loads `superpowers:using-superpowers`, so skills are checked before every task.
  - PreToolUse(ExitPlanMode) is the global twin of the repo's plan-review hook.
  - Stop `check-plan-complete` blocks "done" while the active plan has unchecked items or
    unmodified files.
  - usage-guard warns at 80% and 95% of plan usage, and auto-resumes after a rate-limit reset.
- **RTK (Rust Token Killer):** a PreToolUse Bash hook (`rtk hook claude`) rewrites shell commands
  to compact their output (`git status` becomes `rtk git status`). It cuts tool-output tokens, so
  long sessions stay inside the context window.
- **caveman:** terse output style for the agent's chat replies. It never affects code, commits or
  PR text.
- **Plugins:**
  - `context7`: current library docs, so the agent doesn't recall stale FastAPI or Pydantic APIs.
  - `claude-md-management`: audits the agent instruction files.
  - `frontend-design`, `ui-ux-pro-max`, `design-taste-frontend`, `impeccable`: UI work. Used only
    in stretch S2, after a Claude Design prototype.
  - `obsidian-second-brain`: cross-project knowledge (vendor research, decisions) kept out of the
    repo.
- **Global subagents:** `system-architect` (designs only), `code-gatekeeper` (pre-commit QA),
  `autonomous-test-engineer` (coverage gaps), `documentation-scribe` (doc drift),
  `research-agent` (sourced vendor and library research). The repo vendors only the two agents its
  workflow depends on.
- **Codex** (ChatGPT GitHub connector) is the cross-vendor PR reviewer.

## 4. One-time setup (human)

```powershell
# repo
gh repo create <name> --public --source . --remote origin
git push -u origin main

# branch ruleset on main: require PR, required check "verify", conversation resolution,
# block force pushes and deletions (Settings → Rules → Rulesets), or with gh api.

# Claude PR review: inside Claude Code run /install-github-app (installs the app),
# then create the token and add it as a repo secret:
claude setup-token
gh secret set CLAUDE_CODE_OAUTH_TOKEN

# Codex review: enable the repo in ChatGPT → Codex → Code review settings.

# local hooks
uv sync --all-extras
uv run pre-commit install
```

The AI review workflow skips itself when `CLAUDE_CODE_OAUTH_TOKEN` is not set, so forks and
clones without the secret still get green CI. The core path never needs a key.

## 5. Practices carried over from QuackChat (production RAG SaaS)

| Practice | Origin | Here |
|---|---|---|
| Agent rules file with one imperative per line and links to canonical docs | QuackChat `AGENTS.md` / `CLAUDE.md` trigger index | `AGENTS.md` §1 sources-of-truth table |
| "Diagnose with evidence before fixing"; "don't claim checks passed unless run"; preserve a dirty tree | QuackChat change discipline | `AGENTS.md` §4 |
| Fail-closed hooks with their own test suites | `pre-commit-check.py` and its gate tests | `protect_paths.py`, `require_plan_review.py` and their tests |
| A single verify entry point that mirrors CI, plus a drift test | `local_ci.py` + `test_local_ci.py` | `scripts/verify.py`, and CI calls it rather than re-listing steps |
| Merge gate: P0/P1 must be *fixed*, every AI finding answered | `.github/scripts/pr_gate.py` | `AGENTS.md` §8 severities, `/ship-phase` |
| Codex as an independent PR reviewer | QuackChat PR flow | Same, plus a Claude review action |
| Multi-agent plan review before implementation | `/review-plan` + ExitPlanMode hook | Vendored into the repo |
| Self-review subagent before push | `pr-push-review` → `code-reviewer` | `/ship-phase` |
| Guard tests that ban patterns | AST/grep guard tests | Agent-pointer drift test; "no argument values in logs" test |

## 6. Deliberate deviations (and why)

| QuackChat | Here | Why |
|---|---|---|
| Squash merge | Squash merge | The human chose one commit per PR on `main`; red→green commits stay visible on each PR |
| Personal `bypassPermissions` | Project `acceptEdits` plus a deny list | A regulated-enterprise posture: the repo, not the developer's machine, sets agent permissions |
| No PR template or CODEOWNERS | Both | Team-scale review expectations, made explicit |
| mypy configured but not in CI | `mypy --strict` in `verify` | A small codebase, so strictness is cheap |
| Railway autodeploys on merge | No deploy. The promotion path is documented in `evidence/operate.md` | The brief scope: local plus a credible CI/CD story |
| Changelog gate | None | No customer-facing product surface |

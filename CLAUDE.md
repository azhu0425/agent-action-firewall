# CLAUDE.md

@AGENTS.md

`AGENTS.md` (imported above) is the single source of truth for this repository. **If its contents
are not in your context, read `AGENTS.md` in full before doing anything else.** This file adds only
Claude Code specifics. Put shared rules in `AGENTS.md`, never here.

## Claude Code specifics

- The project settings in `.claude/settings.json` override personal settings. They set the
  permission mode to `acceptEdits`, require asking before `git push` or `gh pr merge`, and deny
  destructive git and `.env` reads. If a hook or permission blocks you, report it and the reason.
  Never try another route to the same effect.
- Hooks:
  - `protect_paths.py` blocks writes to `.claude/protected-paths.txt` entries.
  - `require_plan_review.py` blocks `ExitPlanMode` until `/review-plan` has run.
- Each `PLAN.md` stream runs in its own session: `claude --worktree <stream>` (for example
  `claude --worktree w1-taint`). Start it in plan mode. Run `/review-plan` before exiting plan
  mode, and `/ship-phase <stream-id>` to open the PR.
- Subagents: `code-reviewer` (pre-PR), `red-team-reviewer` (W4-A), and the built-in
  `Explore`/`Plan`. Give each one a self-contained prompt: they do not see this conversation.
- Use the `superpowers` skills as mapped in `AGENTS.md` §13. Use `context7` for FastAPI, Pydantic
  and pytest API questions instead of recalling signatures.
- After context compaction, re-read `AGENTS.md` §2 and your `PLAN.md` stream before
  continuing.
- Memory: project facts can go to auto-memory, but repo rules belong in `AGENTS.md` via a PR so
  every agent and human sees them.

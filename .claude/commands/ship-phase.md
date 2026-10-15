---
description: Ship a PLAN.md stream - verify, self-review, push, open PR, watch CI, answer AI review, hand merge to the human
argument-hint: "<stream id, e.g. W1-A>"
allowed-tools: Bash(git:*), Bash(gh:*), Bash(python:*), Bash(uv:*), Read, Grep, Glob, Edit, Agent
---

# /ship-phase $1

Ship stream $1 of `PLAN.md` as one pull request. Stop and report at any step that fails twice in
the same way. Never work around a gate.

## 1. Preconditions
- `git branch --show-current` must be `w<n>/*` matching stream $1 (or `fix/*`). If it is `main`, **stop**.
- `git diff --name-only origin/main...HEAD` must list only files this stream owns in `PLAN.md`.
  If anything else appears, **stop and report**. Never "fix" it by editing other streams' files.
- `git status`. Make sure the working tree holds only this stream's changes. Do not stage files you
  did not change as part of this stream.
- `git log --oneline origin/main..HEAD`. Confirm that a `test(...) [red]` commit comes before the
  implementation commit. If it does not, say so in the PR. Do not rewrite history.

## 2. Verify
Run `python scripts/verify.py`. It must exit 0. Keep the summary table for the PR body. Use
`superpowers:systematic-debugging` on any failure, and never weaken a test to get green.

## 3. Self-review (fresh context)
Dispatch the `code-reviewer` subagent with this prompt: "Static review of
`git diff origin/main...HEAD` in <repo path>. Rules: AGENTS.md. Focus: PLAN.md 'Review focus'."
- Fix every P0/P1 finding, re-run verify, and re-review. Do at most 2 rounds.
- P2: fix it, or record why not.
- Keep the findings list for the PR comment.

## 4. Commit and push
- Stage explicit paths only (no `git add -A` or `git add .`). Use Conventional Commits, with no
  `Co-authored-by:` trailer for the agent (AGENTS.md §8).
- `git push -u origin HEAD`. The settings ask the human here.

## 5. Open the PR
Run `gh pr create --base main --title "<type>($1): <summary>" --body-file <tmp>`. Fill every
section of `.github/pull_request_template.md` with real content: the verify summary, the
red-commit SHA, the agents used, the interventions, and the risk and rollback. Then post the
self-review findings and their dispositions as a PR comment (`gh pr comment`).

## 6. CI
Run `gh pr checks --watch`. On failure, read the logs (`gh run view --log-failed`), diagnose,
fix, re-run verify locally, then push. Make at most 3 attempts, then stop and report.

## 7. AI review (at most 5 minutes)
Read the review comments from the Claude action and the Codex reviewer
(`gh pr view --comments`, `gh api repos/{owner}/{repo}/pulls/<n>/comments`).
- Apply `superpowers:receiving-code-review`: verify each claim against the code before acting.
- P0/P1: fix with a regression test, then push.
- P2/P3: fix it, or reply with a reason.
- **Reply to every comment.**
- If no review arrives within 5 minutes, note "AI review pending" in the PR and continue.

## 8. Hand back
Report the PR URL, the CI status and the review dispositions. If the human has delegated merging
(AGENTS.md §10, DR-7), the integrator merges once the gates are green and the threads resolved.
Otherwise, hand the merge command to the human:
`gh pr merge <n> --squash --delete-branch`. **Never use `--merge`, `--rebase` or `--admin`**
(AGENTS.md §8).

Then draft rows for the `evidence/agentic-workflow.md` intervention log covering anything the
human corrected during this stream, and ask the human to confirm them.

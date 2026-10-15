## Why
<!-- The PLAN.md stream this PR delivers (e.g. W1-A) and why. Name the agent that ran it. -->

## What
<!-- The behaviour change in 2–5 bullets. Not a file list: reviewers can read the diff. -->

## How verified
<!-- Commands you actually ran and their results. Paste the verify summary. -->
- [ ] `python scripts/verify.py` passes locally (summary below)
- [ ] Red tests were committed before the implementation (commit: `<sha>`)
- [ ] Manual check (if any):

```text
<verify summary>
```

## AI usage
<!-- Be specific. The panel assesses this. -->
- **Agent(s):** <!-- e.g. Claude Code (Opus) implementer; code-reviewer subagent; Codex PR review -->
- **Generated:** <!-- what the agent wrote -->
- **Human changes / interventions:** <!-- what you rejected or corrected, and how you caught it -->
- **Self-review findings:** <!-- P0/P1 fixed; P2 disposition -->

## Risk and rollback
<!-- What could break, how it fails (it must fail closed), and how to roll back (revert this PR). -->

## Checklist
- [ ] Nothing in `AGENTS.md` §2 (invariants) is broken
- [ ] No argument values, PII or secrets in logs, errors or fixtures (synthetic identifiers only)
- [ ] No test weakened, skipped or deleted (or the reason is explained above)
- [ ] Docs updated for any behaviour change (README / `evidence/*`)
- [ ] Every AI review comment answered. P0/P1 fixed

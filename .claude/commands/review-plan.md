---
description: Review a plan with parallel specialist reviewer subagents, then synthesise P0–P2 findings
argument-hint: "path/to/plan.md (optional; defaults to the newest plan file)"
---

# /review-plan

Run this before accepting any non-trivial plan. In this repo, the `require_plan_review.py` hook
blocks `ExitPlanMode` until this command has run in the session.

## 1. Locate the plan
Use `$1` if given. Otherwise use the most recently modified `.md` file under `~/.claude/plans/`
or `.claude/plans/`. Read it in full, along with the `PLAN.md` phase it implements.

## 2. Spawn the reviewers in parallel
Send **one message** with one Agent call per reviewer. Use the `Plan` subagent type, which is
read-only. Each prompt must be self-contained, because subagents do not see this conversation:
give the plan's file path, `AGENTS.md`, `PLAN.md`, and the checklist below. Ask for at most 300
words in this format:

```
### <Role> Review
**Rating**: PASS | CONCERNS | FAIL
#### Findings
- [P0|P1|P2] finding (file/section reference)
#### Recommendations
- specific, actionable change
```

| Reviewer | Always? | Checklist |
|---|---|---|
| architect | yes | Module boundaries, interfaces and signatures, data flow, separation of concerns, what happens on each failure |
| gatekeeper | yes | **Any path to ALLOW on error**, input validation, leakage of argument values or PII, AGENTS.md §2 invariants, completeness against the PLAN.md phase |
| test-reviewer | when the plan writes code | Are the red tests the right ones? Missing edge and failure cases, determinism, whether the tests could pass with a wrong implementation, eval or corpus leakage |

## 3. Synthesise

```
## Plan Review Summary
### Findings by severity
- P0 (must fix before implementing)
- P1 (should fix before implementing)
- P2 (nice to have)
### Disagreements between reviewers (if any) and which view wins, and why
### Approval: Ready | Needs revisions
```

Fold the P0 and P1 items into the plan file before exiting plan mode. Record any notable
finding and its disposition in the `evidence/agentic-workflow.md` review log.

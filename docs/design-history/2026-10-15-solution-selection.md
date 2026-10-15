# Solution selection: multi-agent plan generation and review (2026-10-15)

This is the record of how the problem was chosen, before any code existed. Claude Code drafted
the candidate plans. Independent reviewer subagents, each with a different assessor persona, read
the brief and the candidates. They scored them, voted, and proposed amendments. The human made the
final call, and overrode the first result.

## Reviewer lenses (the same four in both rounds)

1. **Hiring panel:** domain relevance, differentiation, interview discussion value.
2. **Timebox pragmatist:** probability of full completion in 3h, brief coverage, Windows/tooling
   friction.
3. **AI-agent workflow assessor:** evidence of agent use, AI-engineering maturity
   (evals/guardrails), verification rigour.
4. **Tech risk (CPS 234/230):** guarded-failure quality, privacy/security/audit, operability and
   CI/CD.

## Round 1

Candidates:

- A: transaction risk-rules API
- B: scam-message triage with safe abstain and an eval gate
- C: Confirmation-of-Payee name match
- D: fraud alert case pipeline
- E: A plus a golden-set eval

| Lens | A | B | C | D | E | Vote |
|---|---|---|---|---|---|---|
| Hiring panel | 16 | **26** | 22 | 19 | 19 | B |
| Pragmatist | 25 | 21 | 19 | 20 | **26** | E |
| AI workflow | 16 | **25** | 19 | 16 | 21 | B |
| Tech risk | 18 | **26** | 21 | 19 | 19 | B |

B won 3–1. A `/review-plan` pass (architect, gatekeeper, refactor, test) then found one P0 and
several P1s, all folded into the plan:

- **P0:** holdout eval data written after the rules, so it would leak.
- **P1:** redaction would strip scam signals.
- **P1:** the confidence measure was undefined.
- **P1:** FastAPI's 422 response echoes the input.
- **P1:** a timeout cannot kill a synchronous thread.
- **P1:** a fault flag sat in the production path.

**Human override:** the human rejected B as *"too common; many other candidates will build the
same thing."*

## Round 2 (uniqueness required)

Candidates:

- U1: Agent Action Firewall
- U2: money-mule ring graph detector
- U3: adaptive payment-friction engine
- U4: live scam-call copilot (streaming)
- U5: fraud-model release gate

| Lens | U1 | U2 | U3 | U4 | U5 | Vote |
|---|---|---|---|---|---|---|
| Hiring panel | **28** | 23 | 22 | 21 | 22 | U1 |
| Pragmatist | **26** | 22 | 24 | 17 | 18 | U1 |
| AI workflow | **28** | 20 | 20 | 20 | 22 | U1 |
| Tech risk | **29** | 21 | 22 | 21 | 25 | U1 |

U1 won unanimously. The amendments adopted:

- **Lead with a customer story,** because the idea reads as abstract otherwise. This became the
  injected-email transfer headline.
- **Freeze scope** at 4 tools and 5 rule types, with flat YAML.
- **Make injection detection structural** (value-provenance taint over message `source`), not
  keyword matching. The panel would expose a keyword match.
- **Write the human corpus before the rules,** and add a **mutation check** that proves each rule
  carries weight.
- **Fail closed everywhere,** add a hash-chained audit log, and support shadow→enforce promotion
  with `policy_sha256` stamped on every audit record.
- **Dogfood:** a hook stops the coding agent from editing its own eval data, which is the same
  idea the firewall applies to production agents.

Lessons carried into the round-1 review fixes that still apply: commit eval data first, inject
faults through dependency injection, strip input from 422 responses, and keep raw text out of
logs.

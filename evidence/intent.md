# Intent

## Problem statement

Banks are putting LLM agents in front of customers and staff, and those agents can call tools that
move money or data. An agent that reads attacker-controlled text (an email, a web page, a support
ticket) can be steered by it: prompt injection. Model-side defences are probabilistic. The bank
needs a deterministic control at the point where an agent's intent becomes an action, one that a
risk reviewer can read, test and audit.

## Intended users

- **Platform / agent engineers** who host the agents. They call the firewall before executing any
  tool call and act on the verdict.
- **Risk, fraud and security teams** who own the policy (caps, allowlists, bank domains) and review
  the audit trail.
- **Operators** who run it, watch its health and roll policy forward or back.

## Assumptions

- The orchestrator hosting the agent is trusted. It supplies `agent_role`, `customer_id` and
  `known_payees`; the model never does (DR-1).
- Every message in the agent's context can be tagged with its `source`. Only `user` is trusted.
- The agent proposes tool calls as structured JSON, and nothing executes without a verdict.
- A false deny on a legitimate request costs less than a fraudulent transfer or a data leak.

## Constraints

- Fail closed on any error, unknown tool, missing policy or malformed input (AGENTS.md §2.1).
- No argument values, message content or PII in logs, errors or the audit log (§2.2).
- Synthetic data only (§2.3). Offline core path: no LLM, no network, no keys (§2.5).
- A 3-hour, AI-agent-driven build. How the agents were used is assessed alongside the code.

## Out of scope

A real LLM agent on the core path, UI, database, auth, multi-tenancy, policy hot reload, OPA/Rego,
rate limiting, an ML injection classifier and approval resolution. The reasons are in
`decisions.md` ("Not built").

## Success criteria

| Criterion | Measured by |
|---|---|
| The headline injected transfer is DENIED as `TAINTED_ARGUMENT` | Corpus row `atk-001`, `test_headline_injected_transfer_is_denied_as_tainted` |
| Every attack is blocked | Eval gate: attack block rate 1.0 (`eval/thresholds.yaml`) |
| Legitimate requests mostly pass | Benign false-deny rate at most 0.10 |
| Every rule carries weight | Mutation check: disabling any one rule lets an attack through |
| No path to ALLOW on an error | Engine fail-closed tests; `test_evaluate_with_empty_rule_set_denies` |
| Tampering with the audit log is detected | `verify_chain` tests, `cli verify-audit` |
| Anyone can run it from the README | W3 integration checkpoint and W5 fresh-clone release check |

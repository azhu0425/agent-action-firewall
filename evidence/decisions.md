# Decision records

<!-- Integrator-owned. Streams propose records in their PR body; the integrator collects them. -->

## DR-1: Trust boundary of an evaluation request

- **Context.** The self-review of W0a pointed out that a compromised agent could put an attacker's
  payee into `known_payees`, or claim a more privileged `agent_role`. Either would defeat
  NEW_PAYEE and ROLE_ALLOWLIST.
- **Decision.** These fields are supplied by the orchestrator, meaning the service that hosts the
  agent and owns the customer session. They are never taken from model output. The firewall
  treats only `call` and non-`user` messages as untrusted.
- **Consequences.** It stays simple and stateless. In production the firewall would look up
  known payees by `customer_id` from a store it owns, and derive the role from the calling
  service's identity (mTLS / workload identity), not from the request body.

## Not built (deliberately)

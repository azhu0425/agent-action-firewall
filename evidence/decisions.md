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

## DR-2: Deterministic rules, most-restrictive-wins, fail closed

- **Context.** The gateway has to be explainable to a risk reviewer, and predictable when
  something goes wrong.
- **Decision.**
  - Six pure rule functions, each returning findings that carry reason codes.
  - The engine takes the most severe verdict. Every reason is returned, de-duplicated.
  - An empty rule set, a missing policy, a rule exception, or a rule that breaks its contract
    (an engine-only reason, or an ALLOW finding) all produce DENY.
  - Each rule gets deep copies of its inputs, so rules can't affect each other.
- **Shadow mode** returns ALLOW together with `would_be`, so a new policy can be measured before
  it is enforced. It never relaxes NOT_ALLOWLISTED, INVALID_ARGUMENT or any error path. Unknown
  tools and malformed input are denied in every mode, and §2.1 has no exceptions.
- **Rejected.**
  - OPA/Rego: an extra runtime and language for six rules.
  - An LLM classifier on the decision path: not deterministic, not auditable, and it needs keys.
- **Trade-off.**
  - Rule failures are logged with only the allowlisted fields (Codex review): no rule name and no
    exception type. Finding which rule failed means replaying the request id locally.
  - A buggy rule therefore costs debugging time, never an ALLOW.

## DR-3: Tamper-evident audit without storing values

- **Decision.**
  - The audit log is append-only JSONL with a hash chain.
  - Records store `args_sha256` (canonical JSON of the arguments), never the arguments
    themselves.
  - Each record carries the policy hash and the engine version.
  - Before appending, the log recomputes the hash of its last record and refuses to append if
    that record has been tampered with (Codex review).
- **Limits** (documented in the module):
  - The arguments have low entropy (BSB + account + amount), so a plain SHA-256 can be
    brute-forced. In production this would be an HMAC with a key from a KMS.
  - Truncating the tail of the log, or rewriting the whole file, can only be detected against an
    external anchor. `chain_head()` exposes the head hash so it can be anchored externally
    (WORM storage, a SIEM).
  - Two concurrent writers can fork the chain. Production needs a single writer or a log service.
- **Why.** CPS 234 auditability, without turning the audit log into a PII store.

## DR-4: Taint tracking is lexical value provenance

- **Decision.**
  - Every source except `user` is untrusted, including the assistant's own turns.
  - Values are normalised: NFKC, casefold, keep `[a-z0-9@]`. Floats with integer values become
    ints.
  - An argument in `taint_fields` is tainted when its normalised value (at least 6 characters)
    appears in untrusted content and does not appear as a whole token in any user turn.
- **Catches:** values copied verbatim, values re-rendered with different spacing, dashes,
  currency or Unicode forms, and values hidden inside a longer number the user typed.
- **Misses** (accepted):
  - paraphrase or spelled-out numbers
  - values split across messages
  - base64 and other encodings
  - homoglyphs that NFKC doesn't fold
  - a user induced to retype the value
  - values shorter than 6 characters
- **Backstop:** caps, NEW_PAYEE and PII_EGRESS. A semantic LLM judge is future work, and would
  run off the decision path (stretch S4).

## DR-5: Known payees are exempt from payee taint; the scripted agent is a valid test double

- **Context.** The independent corpus author pointed out a false-deny case: "pay my landlord
  again", where the agent looks up the account in a tool and the user never types the digits.
- **Decision.**
  - For `transfer_funds`, `bsb`/`account_number` taint is dropped when the (BSB, account) pair
    matches a known payee exactly, compared as a pair and never concatenated.
  - Money still can't reach a new account without human approval (NEW_PAYEE), and the caps still
    apply.
- **Test double.** The firewall's only input is an `EvalRequest`. A real LLM that follows an
  injected instruction emits the same tool-call JSON as `firewall/demo.py`'s naive agent. The
  scripted agent therefore tests the product boundary exactly, deterministically, offline and for
  free.
- **What it does not measure:** how often a real model is fooled. That is out of scope, because
  the firewall has to hold even when the model is fully compromised. Stretch S3 records real
  local-model traces as cassettes.

## DR-6: Conservative PII egress and closed tool schemas

- **Decision.**
  - Every known tool has a closed argument set. Unknown arguments such as `cc`, `bcc` or a second
    payee field are INVALID_ARGUMENT/DENY.
  - `to` must be a single bare address.
  - Outbound email to any non-bank domain is scanned after NFKC with separators removed. Any run
    of 6 or more digits is treated as possible account data, which covers BSBs, accounts and
    cards.
- **Trade-off.** Dates (`2026-10-15`), long phone numbers and order numbers in external emails
  will be flagged (DENY). For a bank assistant, a false deny on an external email is cheaper
  than leaking account data. The benign corpus measures the cost: 0/16 false denies today.
- **Account numbers** are 5–10 digits. The first bound of 6–10 came from an integrator review
  instruction, and the human-approved corpus showed it wrong (`ben-011`). The acceptance tests
  win.

## DR-7: Humans own acceptance; agents own implementation

- **Decision.**
  - The eval corpus, its hash lock, the thresholds and the agent guardrails are human-owned. A
    PreToolUse hook, CODEOWNERS and a CI hash test enforce it.
  - The corpus was written by an independent test-author agent from the spec alone. The human
    reviewed it and placed it with their own command, and it merged before the rules.
  - Independent agents wrote the corpus and the rules. They agreed on 35 of 36 cases on the first
    run.
- **Delegation.** The human chose to delegate push, PR and merge to the integrator agent, and
  removed the ask-before-push list. The main-branch ruleset still requires a PR, a green
  `verify` and resolved review threads, and allows squash merges only, so each PR lands on
  `main` as one commit. The red→green sequence stays visible in the PR's own commit list.
  The human switched from merge commits to squash on 2026-10-15.
- **Synthetic data.** All BSBs use the `000` prefix. `062-000`, used early on, is a live CBA
  branch. Codex caught it; every Claude agent had missed it.

## DR-8: A React operator console in its own container

- **Context.** The service is an API. Interviewers opening `docker compose up` saw nothing, and
  the core insight (where a tainted value came from) is hard to see in raw JSON.
- **Decision.** A Vite + React + TypeScript console (`web/`) served by unprivileged nginx, which
  also proxies `/api` to the firewall, so the browser has one origin and the API needs no CORS.
  New runtime dependencies: react, react-dom, motion, @phosphor-icons/react, zod, @fontsource
  (self-hosted fonts). One new read-only API endpoint, `GET /v1/audit`, returns value-free
  records with `args_sha256` cut to 8 hex characters (DR-3) and chain status.
- **Verification.** The web image cannot build unless typecheck, lint, unit tests and the
  production build pass. Web checks run in their own CI job rather than in `scripts/verify.py`,
  because `npm ci` needs the network and verify stays offline (AGENTS.md §2.5).
- **Limits.** Local demo with no authentication: both ports are bound to 127.0.0.1. Production
  would put the console behind SSO with role-based access, and would not expose the audit trail
  to every operator.

## Not built (deliberately)

| Not built | Why |
|---|---|
| A real LLM agent on the core path | Needs keys, is non-deterministic, and is unnecessary to test the boundary (DR-5). Stretch S3 records local-model traces offline |
| Console authentication | Local demo only, bound to 127.0.0.1 (DR-8) |
| Database, auth, multi-tenancy | Stateless evaluation is enough for the slice. Production shape is in `operate.md` |
| Policy hot reload | A policy change is a deploy (PR, CI replays the corpus, revert to roll back) |
| OPA/Rego, rate limiting, an ML injection classifier | Scope (DR-2, DR-4) |
| Cross-process audit lock / multiple workers | Single writer per audit log (one uvicorn worker). Production would use an audit log service (DR-3, Codex review of PR #14) |
| HMAC on audit hashes, external chain anchoring | Needs a KMS or WORM store (DR-3) |
| Approval resolution endpoint | Stretch S1. REQUIRE_HUMAN_APPROVAL parks the call |

# Operate

## Running

| How | Command |
|---|---|
| Local API | `uvicorn firewall.api:app` (port 8000): `POST /v1/evaluate`, `GET /health` |
| Container | `docker build -t firewall . && docker run -p 8000:8000 firewall` |
| Batch replay | `python -m firewall.cli replay <traces.jsonl>`: exits non-zero on any mismatch |
| Demo | `python -m firewall.cli demo`: the naive agent with and without the firewall |
| Audit check | `python -m firewall.cli verify-audit <log>`: index of the first bad record, or intact |

The container runs as a non-root user with `APP_ENV=prod`, and its `HEALTHCHECK` calls `/health`.

**Single writer.** Each audit log must have exactly one writing process: run one uvicorn worker
per `FIREWALL_AUDIT_LOG` (no `--workers N` on a shared file). Two writers can fork the hash chain,
because reading the last hash and appending are not atomic across processes. To scale out, give
each replica its own log, or ship records to a single log service. A cross-process lock is on the
"Not built" list (DR-3).

<!-- TODO(W3): confirm the /health body, status codes and CLI exit codes against firewall/api.py and firewall/cli.py. -->

## Logs and status

- **Logs** are one JSON object per line on stderr: `ts`, `level`, `logger`, `message`,
  `request_id`, plus only allowlisted fields (`tool`, `verdict`, `reasons`, `latency_ms`, `status`,
  `path`, `method`, `error_type`). Argument values, message content and exception text are never
  emitted. Every response carries `X-Request-ID`; a client-supplied one is kept if well-formed.
- **Status.** `/health` reports ok when a policy is loaded and degraded when it is not. A degraded
  instance still answers, but denies everything (`POLICY_UNLOADED`).
- **Audit** is `FIREWALL_AUDIT_LOG` (default `audit/audit.jsonl`): one hash-chained record per
  decision with verdict, reasons, tool, role, `args_sha256`, `policy_sha256` and engine version.
- **What to alert on:** health degraded; any `EVALUATOR_ERROR` or `POLICY_UNLOADED`; a step change
  in the DENY or APPROVAL rate; `verify-audit` reporting a bad record.

## Configuration and secrets

All configuration is environment variables, validated at startup by pydantic-settings and
documented in `.env.example`:

| Variable | Default | Notes |
|---|---|---|
| `FIREWALL_POLICY_PATH` | `policy/policy.yaml` | Missing or invalid means every call is DENY |
| `FIREWALL_AUDIT_LOG` | `audit/audit.jsonl` | The only path the process writes |
| `APP_ENV` | `dev` | `dev`, `test` or `prod` |
| `FIREWALL_ALLOW_SHADOW_IN_PROD` | `false` | Shadow mode in prod needs this explicit opt-in |
| `LOG_LEVEL` | `INFO` | |

The core path needs no secrets. `.env` is gitignored and never read by agents. In production the
audit HMAC key (DR-3) would come from a KMS, never from a file.

## Failure modes and degrade behaviour

The firewall degrades to **deny**, never to allow. The full table is in `design.md`.

| Situation | What the caller sees | Operator action |
|---|---|---|
| Policy missing or invalid at startup | Every call DENY `POLICY_UNLOADED`; health degraded | Fix or revert the policy commit; redeploy |
| A rule crashes on some input | That call DENY `EVALUATOR_ERROR` | Replay the request id locally to find the rule (DR-2) |
| Malformed request | 422 with no echoed input | Fix the orchestrator's payload |
| Audit append fails | <!-- TODO(W3): document the API's behaviour on AuditError --> | Check disk and the chain with `verify-audit` |
| Firewall unreachable | Orchestrator must treat it as DENY (fail closed on the caller side) | Scale out or restore the service |

## Shadow to enforce

1. Ship the new policy with `mode: shadow`. Each call returns ALLOW with `would_be` set to the
   verdict enforce mode would give; unknown tools and malformed arguments are still denied.
2. Compare `would_be` against what actually happened, from the audit log, for an agreed period.
3. Flip to `mode: enforce` in a reviewed PR. The policy hash on each audit record shows exactly
   which policy decided each call.

Shadow mode is refused when `APP_ENV=prod` unless `FIREWALL_ALLOW_SHADOW_IN_PROD=true`.

## Rollback

A policy change is a code change. Rollback is `git revert` of the policy commit, which goes through
the same PR, CI and corpus replay, then a redeploy. The previous image can also be redeployed
directly; its policy hash is on every audit record it wrote.

## Local to cloud

| Concern | Local | Cloud |
|---|---|---|
| Runtime | `uvicorn` or `docker run` | The same image on a container platform, internal only, behind mTLS |
| Policy | File in the repo | Baked into the image, or mounted read-only from a versioned store |
| Trusted context | Sent in the request body | Role from workload identity; known payees from a payee store (DR-1) |
| Audit | Local JSONL | Single writer or log service, WORM / SIEM, external chain-head anchor, HMAC from KMS (DR-3) |
| Logs | stderr | Platform log pipeline with alerts as above |

### CI/CD promotion

1. **PR checks:** `verify` (lint, types, tests, coverage, eval gate, mutation), `security.yml`
   (bandit, pip-audit, gitleaks, container build and `/health` smoke), Codex and Claude review.
2. **Approvals:** CODEOWNERS review for the policy, corpus, thresholds, CI and agent config; the
   `main` ruleset requires a PR, a green `verify` and resolved threads, with merge commits only.
3. **Deploy (not built):** build once on `main`, push the image by digest, deploy to staging in
   shadow mode, then to production in enforce mode behind a manual approval.
4. **Rollback:** redeploy the previous digest, or revert the commit and let the pipeline ship it.

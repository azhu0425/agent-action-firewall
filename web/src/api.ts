// The only module that talks to the firewall. Every response is validated before use, and
// request bodies are never logged (AGENTS.md §2.2; ESLint bans console calls).
import {
  AuditResponseSchema,
  DecisionSchema,
  HealthSchema,
  ValidationErrorSchema,
  type AuditResponse,
  type Decision,
  type EvalRequest,
  type Health,
} from "./schemas";

const BASE = "/api";

export type Result<T> =
  | { kind: "ok"; value: T }
  | { kind: "unreachable" }
  | { kind: "rejected"; problems: string[] }
  | { kind: "failed"; status: number };

async function call<T>(path: string, parse: (data: unknown) => T, init?: RequestInit): Promise<Result<T>> {
  let response: Response;
  try {
    response = await fetch(BASE + path, init);
  } catch {
    return { kind: "unreachable" };
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    return { kind: "failed", status: response.status };
  }
  if (response.status === 422) {
    const parsed = ValidationErrorSchema.safeParse(data);
    const problems = parsed.success
      ? parsed.data.details.map((d) => `${d.loc.slice(1).join(".") || "body"}: ${d.msg}`)
      : ["The firewall rejected the request as malformed."];
    return { kind: "rejected", problems };
  }
  try {
    return { kind: "ok", value: parse(data) };
  } catch {
    return { kind: "failed", status: response.status };
  }
}

// /health answers 503 with a valid body when degraded, so it is parsed on any status.
export function getHealth(): Promise<Result<Health>> {
  return call("/health", (data) => HealthSchema.parse(data));
}

export function evaluate(request: EvalRequest): Promise<Result<Decision>> {
  return call("/v1/evaluate", (data) => DecisionSchema.parse(data), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
}

export function getAudit(limit = 50): Promise<Result<AuditResponse>> {
  return call(`/v1/audit?limit=${limit}`, (data) => AuditResponseSchema.parse(data));
}

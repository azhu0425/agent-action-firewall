import { describe, expect, it } from "vitest";
import { AuditResponseSchema, DecisionSchema, HealthSchema } from "./schemas";

const decision = {
  request_id: "demo-attack",
  verdict: "DENY",
  reasons: ["TAINTED_ARGUMENT"],
  findings: [{ reason: "TAINTED_ARGUMENT", verdict: "DENY", argument: "bsb" }],
  shadow: false,
  would_be: null,
  policy_sha256: "97c4",
};

describe("DecisionSchema", () => {
  it("accepts a firewall decision", () => {
    expect(DecisionSchema.parse(decision).verdict).toBe("DENY");
  });

  it("rejects an unknown verdict", () => {
    expect(DecisionSchema.safeParse({ ...decision, verdict: "MAYBE" }).success).toBe(false);
  });

  it("rejects a missing reasons list", () => {
    const { reasons: _reasons, ...rest } = decision;
    expect(DecisionSchema.safeParse(rest).success).toBe(false);
  });
});

describe("HealthSchema", () => {
  it("accepts ok and degraded", () => {
    expect(HealthSchema.parse({ status: "ok", policy_sha256: "abc" }).status).toBe("ok");
    expect(HealthSchema.parse({ status: "degraded", reason: "policy_unloaded" }).status).toBe(
      "degraded",
    );
  });
});

describe("AuditResponseSchema", () => {
  it("accepts records and chain status", () => {
    const parsed = AuditResponseSchema.parse({
      records: [
        {
          ts: "2026-10-15T04:43:22+00:00",
          request_id: "r1",
          tool: "transfer_funds",
          agent_role: "customer_assistant",
          verdict: "DENY",
          reasons: ["NEW_PAYEE"],
          shadow: false,
          args_sha256: "bc49d439",
        },
      ],
      chain: { ok: true, count: 1, head: "abcd", first_bad: null },
    });
    expect(parsed.records).toHaveLength(1);
  });
});

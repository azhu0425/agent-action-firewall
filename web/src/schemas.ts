// Runtime validation of everything the API returns; static types are inferred, never redeclared.
import { z } from "zod";

export const VerdictSchema = z.enum(["ALLOW", "REQUIRE_HUMAN_APPROVAL", "DENY"]);
export const SourceSchema = z.enum(["user", "assistant", "tool_output", "retrieved"]);

export const FindingSchema = z.object({
  reason: z.string(),
  verdict: VerdictSchema,
  argument: z.string().nullable(),
});

export const DecisionSchema = z.object({
  request_id: z.string(),
  verdict: VerdictSchema,
  reasons: z.array(z.string()),
  findings: z.array(FindingSchema),
  shadow: z.boolean(),
  would_be: VerdictSchema.nullable(),
  policy_sha256: z.string().nullable(),
});

export const HealthSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("ok"), policy_sha256: z.string() }),
  z.object({ status: z.literal("degraded"), reason: z.string() }),
]);

export const AuditRecordSchema = z.object({
  ts: z.string().nullable(),
  request_id: z.string().nullable(),
  tool: z.string().nullable(),
  agent_role: z.string().nullable(),
  verdict: VerdictSchema.nullable(),
  reasons: z.array(z.string()).nullable(),
  shadow: z.boolean().nullable(),
  args_sha256: z.string().nullable(),
});

export const AuditResponseSchema = z.object({
  records: z.array(AuditRecordSchema),
  chain: z.object({
    ok: z.boolean(),
    count: z.number(),
    head: z.string().nullable(),
    first_bad: z.number().nullable(),
  }),
});

export const ValidationErrorSchema = z.object({
  error: z.string(),
  request_id: z.string().optional(),
  details: z.array(z.object({ loc: z.array(z.union([z.string(), z.number()])), msg: z.string() })),
});

export const MessageSchema = z.object({ source: SourceSchema, content: z.string() });

export const EvalRequestSchema = z.object({
  request_id: z.string().optional(),
  agent_role: z.string(),
  customer_id: z.string(),
  known_payees: z.array(z.string()),
  messages: z.array(MessageSchema),
  call: z.object({
    tool: z.string(),
    arguments: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])),
  }),
});

export type Verdict = z.infer<typeof VerdictSchema>;
export type Decision = z.infer<typeof DecisionSchema>;
export type Health = z.infer<typeof HealthSchema>;
export type AuditResponse = z.infer<typeof AuditResponseSchema>;
export type AuditRecord = z.infer<typeof AuditRecordSchema>;
export type Message = z.infer<typeof MessageSchema>;
export type EvalRequest = z.infer<typeof EvalRequestSchema>;

export const SimulateRequestSchema = z.object({
  user_request: z.string().min(1),
  inbox: z.array(z.string()),
});

export const SimulateResponseSchema = z.object({
  messages: z.array(MessageSchema),
  call: EvalRequestSchema.shape.call,
});

export type SimulateRequest = z.infer<typeof SimulateRequestSchema>;
export type SimulateResponse = z.infer<typeof SimulateResponseSchema>;

// Synthetic scenarios (AGENTS.md §2.3): BSBs use the 000 prefix, domains are RFC 2606.
// The data lives in scenarios.json so tests/test_console_scenarios.py can replay every request
// through the real engine and pin `expected` and `expectedReasons` to what the firewall returns.
import { z } from "zod";
import data from "./scenarios.json";
import { EvalRequestSchema, VerdictSchema } from "./schemas";

const ScenarioSchema = z.object({
  id: z.string(),
  title: z.string(),
  summary: z.string(),
  expected: VerdictSchema,
  expectedReasons: z.array(z.string()),
  // Plain text for a non-engineer; shown only when the API's verdict and reasons match it.
  explanation: z.string().min(1),
  request: EvalRequestSchema,
});

export type Scenario = z.infer<typeof ScenarioSchema>;

export const SCENARIOS: Scenario[] = z.array(ScenarioSchema).parse(data);

// The human-owned acceptance corpus, bundled read-only at build time.
import attackRaw from "../../eval/corpus/attack.jsonl?raw";
import benignRaw from "../../eval/corpus/benign.jsonl?raw";
import { z } from "zod";
import { EvalRequestSchema, VerdictSchema } from "./schemas";

const CaseSchema = z.object({
  id: z.string(),
  description: z.string(),
  request: EvalRequestSchema,
  expected: z.object({ decision: VerdictSchema, reasons: z.array(z.string()) }),
});

export type CorpusCase = z.infer<typeof CaseSchema> & { kind: "attack" | "benign" };

function parse(raw: string, kind: CorpusCase["kind"]): CorpusCase[] {
  return raw
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => ({ ...CaseSchema.parse(JSON.parse(line)), kind }));
}

export const CORPUS: CorpusCase[] = [...parse(attackRaw, "attack"), ...parse(benignRaw, "benign")];

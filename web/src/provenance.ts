// Display-only provenance: where did a tainted argument's value appear in the session?
// Mirrors firewall/taint.py so the highlight matches what the firewall saw. The verdict itself
// always comes from the API; this only shows the evidence (README, DESIGN.md).
import type { Message } from "./schemas";

// The firewall ignores values shorter than this (policy min_taint_length, DR-4).
export const MIN_TAINT_LENGTH = 6;

const KEEP = /[a-z0-9@]/;

export function normalise(value: string): string {
  return [...value.normalize("NFKC").toLowerCase()].filter((c) => KEEP.test(c)).join("");
}

export interface Span {
  start: number;
  end: number;
}

// Normalise char by char, remembering which original offset each kept char came from, so a
// match in normalised space maps back to the exact characters on screen.
function normaliseWithOffsets(text: string): { flat: string; offsets: number[] } {
  let flat = "";
  const offsets: number[] = [];
  let index = 0;
  for (const char of text) {
    for (const piece of char.normalize("NFKC").toLowerCase()) {
      if (KEEP.test(piece)) {
        flat += piece;
        offsets.push(index);
      }
    }
    index += char.length;
  }
  return { flat, offsets };
}

export function findSpans(text: string, value: string, minLength = MIN_TAINT_LENGTH): Span[] {
  const needle = normalise(value);
  if (needle.length < minLength) return [];
  const { flat, offsets } = normaliseWithOffsets(text);
  const spans: Span[] = [];
  let from = flat.indexOf(needle);
  while (from !== -1) {
    const start = offsets[from]!;
    const lastOffset = offsets[from + needle.length - 1]!;
    const lastChar = String.fromCodePoint(text.codePointAt(lastOffset)!);
    spans.push({ start, end: lastOffset + lastChar.length });
    from = flat.indexOf(needle, from + needle.length);
  }
  return spans;
}

export interface TaintedSpan extends Span {
  messageIndex: number;
  argument: string;
}

export function taintedSpans(
  messages: readonly Pick<Message, "source" | "content">[],
  args: Record<string, unknown>,
  taintedArguments: readonly string[],
): TaintedSpan[] {
  const result: TaintedSpan[] = [];
  for (const argument of taintedArguments) {
    const raw = args[argument];
    if (typeof raw !== "string" && typeof raw !== "number") continue;
    messages.forEach((message, messageIndex) => {
      if (message.source === "user") return;
      for (const span of findSpans(message.content, String(raw))) {
        result.push({ ...span, messageIndex, argument });
      }
    });
  }
  return result;
}

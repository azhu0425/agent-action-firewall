import { describe, expect, it } from "vitest";
import { SCENARIOS } from "./scenarios";

describe("scenarios", () => {
  it("gives every scenario a plain-language explanation without markdown", () => {
    for (const scenario of SCENARIOS) {
      expect(scenario.explanation.trim().length).toBeGreaterThan(40);
      expect(scenario.explanation).not.toContain("`");
    }
  });

  it("keeps scenario ids unique", () => {
    expect(new Set(SCENARIOS.map((s) => s.id)).size).toBe(SCENARIOS.length);
  });
});

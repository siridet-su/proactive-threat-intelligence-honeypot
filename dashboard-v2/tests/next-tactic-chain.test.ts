import { describe, expect, it } from "vitest";

import { buildNextTacticChain } from "@/lib/next-tactic-chain";

describe("Next-Tactic observed-to-advisory chain", () => {
  it("keeps observed tactics ordered and appends one labelled forecast", () => {
    expect(buildNextTacticChain(
      [{ tactic: "discovery" }, { tactic: "execution" }],
      { tactic: "persistence" },
    )).toEqual([
      { tactic: "discovery", kind: "observed" },
      { tactic: "execution", kind: "observed" },
      { tactic: "persistence", kind: "predicted" },
    ]);
  });

  it("marks an ended-session result as historical and emits no invalid node", () => {
    expect(buildNextTacticChain(
      [{ tactic: "discovery" }],
      { tactic: "execution", historical: true },
    )).toEqual([
      { tactic: "discovery", kind: "observed" },
      { tactic: "execution", kind: "historical" },
    ]);
    expect(buildNextTacticChain([{ tactic: "discovery" }], null)).toEqual([
      { tactic: "discovery", kind: "observed" },
    ]);
  });

  it("does not invent a forecast when the projection is empty", () => {
    expect(buildNextTacticChain([], { tactic: " " })).toEqual([]);
  });
});

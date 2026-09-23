import { describe, expect, it } from "vitest";

import { resolveRovingTabIndex } from "../src/components/filesystem/tabSemantics";

describe("FSV-012A roving tab navigation", () => {
  it.each([
    ["ArrowRight", 0, 3, "horizontal", 1],
    ["ArrowRight", 2, 3, "horizontal", 0],
    ["ArrowLeft", 0, 3, "horizontal", 2],
    ["ArrowLeft", 2, 3, "horizontal", 1],
    ["Home", 2, 3, "horizontal", 0],
    ["End", 0, 3, "horizontal", 2],
    ["ArrowDown", 2, 3, "vertical", 0],
    ["ArrowUp", 0, 3, "vertical", 2],
  ] as const)("maps %s from %i/%i in %s tabs to %i", (key, current, count, orientation, expected) => {
    expect(resolveRovingTabIndex(key, current, count, orientation)).toBe(expected);
  });

  it("ignores unrelated keys, orientation-mismatched arrows, and invalid ranges", () => {
    expect(resolveRovingTabIndex("Enter", 0, 2)).toBeNull();
    expect(resolveRovingTabIndex("ArrowDown", 0, 2, "horizontal")).toBeNull();
    expect(resolveRovingTabIndex("ArrowRight", -1, 2)).toBeNull();
    expect(resolveRovingTabIndex("ArrowRight", 0, 0)).toBeNull();
  });
});

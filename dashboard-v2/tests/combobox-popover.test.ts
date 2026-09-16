import { describe, expect, it } from "vitest";

import {
  calculateNextComboboxIndex,
  findTypeaheadIndex,
} from "../src/components/filesystem/ComboboxPopover";

describe("accessible combobox navigation helpers (FS-013)", () => {
  describe("calculateNextComboboxIndex", () => {
    it("advances index forward on positive delta", () => {
      expect(calculateNextComboboxIndex(0, 1, 5)).toBe(1);
      expect(calculateNextComboboxIndex(1, 1, 5)).toBe(2);
      expect(calculateNextComboboxIndex(3, 1, 5)).toBe(4);
    });

    it("wraps around to index 0 on reaching the end by default", () => {
      expect(calculateNextComboboxIndex(4, 1, 5)).toBe(0);
      expect(calculateNextComboboxIndex(4, 1, 5, { loop: true })).toBe(0);
    });

    it("clamps at the end when loop is false", () => {
      expect(calculateNextComboboxIndex(4, 1, 5, { loop: false })).toBe(4);
    });

    it("starts at index 0 when moving forward from unselected (-1)", () => {
      expect(calculateNextComboboxIndex(-1, 1, 5)).toBe(0);
    });

    it("steps backward on negative delta", () => {
      expect(calculateNextComboboxIndex(4, -1, 5)).toBe(3);
      expect(calculateNextComboboxIndex(2, -1, 5)).toBe(1);
      expect(calculateNextComboboxIndex(1, -1, 5)).toBe(0);
    });

    it("wraps to last index when stepping back from index 0 without allowInputFocus", () => {
      expect(calculateNextComboboxIndex(0, -1, 5)).toBe(4);
      expect(calculateNextComboboxIndex(0, -1, 5, { loop: true })).toBe(4);
    });

    it("returns -1 when stepping back from index 0 with allowInputFocus (to focus search input)", () => {
      expect(calculateNextComboboxIndex(0, -1, 5, { allowInputFocus: true })).toBe(-1);
    });

    it("clamps to 0 when loop is false and stepping back from 0", () => {
      expect(calculateNextComboboxIndex(0, -1, 5, { loop: false, allowInputFocus: false })).toBe(0);
    });

    it("jumps to index 0 on 'home'", () => {
      expect(calculateNextComboboxIndex(3, "home", 5)).toBe(0);
      expect(calculateNextComboboxIndex(0, "home", 5)).toBe(0);
    });

    it("jumps to last index on 'end'", () => {
      expect(calculateNextComboboxIndex(0, "end", 5)).toBe(4);
      expect(calculateNextComboboxIndex(2, "end", 5)).toBe(4);
    });

    it("handles empty lists gracefully", () => {
      expect(calculateNextComboboxIndex(0, 1, 0)).toBe(0);
      expect(calculateNextComboboxIndex(0, 1, 0, { allowInputFocus: true })).toBe(-1);
    });
  });

  describe("findTypeaheadIndex", () => {
    const sessionItems = [
      { ip: "10.58.33.209", id: "sess-1" },
      { ip: "172.16.0.4", id: "sess-2" },
      { ip: "192.168.1.10", id: "sess-3" },
      { ip: "10.0.0.1", id: "sess-4" },
      { ip: "192.168.1.25", id: "sess-5" },
    ];

    const getIp = (item: (typeof sessionItems)[number]) => item.ip;

    it("finds matching item forward from startIndex", () => {
      // From index 0 (10.58.33.209), typing "192" should find index 2 (192.168.1.10)
      expect(findTypeaheadIndex(sessionItems, getIp, "192", 0)).toBe(2);

      // From index 2 (192.168.1.10), typing "192" should find index 4 (192.168.1.25)
      expect(findTypeaheadIndex(sessionItems, getIp, "192", 2)).toBe(4);
    });

    it("wraps around to the beginning when no forward match exists", () => {
      // From index 4 (192.168.1.25), typing "10." should wrap around and find index 0 (10.58.33.209)
      expect(findTypeaheadIndex(sessionItems, getIp, "10.", 4)).toBe(0);

      // From index 4, typing "172" should wrap around and find index 1 (172.16.0.4)
      expect(findTypeaheadIndex(sessionItems, getIp, "172", 4)).toBe(1);
    });

    it("performs case-insensitive matching", () => {
      const paths = [
        { path: "/bin" },
        { path: "/etc/ssh" },
        { path: "/home/admin" },
        { path: "/var/log" },
      ];
      const getPath = (item: (typeof paths)[number]) => item.path;

      expect(findTypeaheadIndex(paths, getPath, "/H", 0)).toBe(2);
      expect(findTypeaheadIndex(paths, getPath, "/v", 0)).toBe(3);
      expect(findTypeaheadIndex(paths, getPath, "/ETC", 0)).toBe(1);
    });

    it("returns -1 when query has no matches", () => {
      expect(findTypeaheadIndex(sessionItems, getIp, "999.", 0)).toBe(-1);
      expect(findTypeaheadIndex(sessionItems, getIp, "", 0)).toBe(-1);
      expect(findTypeaheadIndex([], (x: string) => x, "abc", 0)).toBe(-1);
    });
  });
});

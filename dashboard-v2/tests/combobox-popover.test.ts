import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuditFilterControls } from "../src/components/filesystem/AuditFilterControls";
import { AuditSessionSelect } from "../src/components/filesystem/AuditSessionSelect";
import { AuditSessionSearchManager } from "../src/components/filesystem/auditSessionSearchManager";
import {
  calculateNextComboboxIndex,
  ComboboxPopover,
  ComboboxSearchInput,
  determineFocusTarget,
  findTypeaheadIndex,
} from "../src/components/filesystem/ComboboxPopover";
import type { FilesystemClosedSession } from "../src/lib/dashboardTypes";


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

  describe("determineFocusTarget (FA-007)", () => {
    it("returns null when popover is already open", () => {
      expect(determineFocusTarget("ArrowDown", true)).toBeNull();
      expect(determineFocusTarget("ArrowUp", true)).toBeNull();
      expect(determineFocusTarget("Enter", true)).toBeNull();
      expect(determineFocusTarget(" ", true)).toBeNull();
    });

    it("returns 'first' when opening with ArrowDown", () => {
      expect(determineFocusTarget("ArrowDown", false)).toBe("first");
    });

    it("returns 'last' when opening with ArrowUp", () => {
      expect(determineFocusTarget("ArrowUp", false)).toBe("last");
    });

    it("returns 'search' when opening with Enter or Space", () => {
      expect(determineFocusTarget("Enter", false)).toBe("search");
      expect(determineFocusTarget(" ", false)).toBe("search");
    });

    it("returns null for non-opening keys when closed", () => {
      expect(determineFocusTarget("Escape", false)).toBeNull();
      expect(determineFocusTarget("Tab", false)).toBeNull();
      expect(determineFocusTarget("a", false)).toBeNull();
    });
  });

  describe("AuditSessionSearchManager (FA-007)", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("fires onClearSearch exactly once across different close reasons", () => {
      const onClearSearch = vi.fn();
      const manager = new AuditSessionSearchManager({ onClearSearch });

      // Open and close via escape
      manager.open();
      expect(manager.getIsOpen()).toBe(true);
      manager.close("escape");
      expect(manager.getIsOpen()).toBe(false);
      expect(onClearSearch).toHaveBeenCalledTimes(1);

      // Repeated close when already closed does not re-fire onClearSearch
      manager.close("escape");
      expect(onClearSearch).toHaveBeenCalledTimes(1);

      // Open and close via select
      manager.open();
      manager.close("select");
      expect(onClearSearch).toHaveBeenCalledTimes(2);

      // Open and close via toggle
      manager.open();
      manager.close("toggle");
      expect(onClearSearch).toHaveBeenCalledTimes(3);

      // Open and close via outside
      manager.open();
      manager.close("outside");
      expect(onClearSearch).toHaveBeenCalledTimes(4);
    });

    it("cancels pending debounced search immediately on close", () => {
      const onSearch = vi.fn();
      const onClearSearch = vi.fn();
      const manager = new AuditSessionSearchManager({
        onSearch,
        onClearSearch,
        debounceMs: 200,
      });

      manager.open();
      manager.setSearchQuery("10.58");
      expect(manager.isDebouncePending()).toBe(true);

      // Fast-forward 100ms (before debounce expires)
      vi.advanceTimersByTime(100);
      expect(onSearch).not.toHaveBeenCalled();

      // Close before timer fires
      manager.close("escape");
      expect(manager.isDebouncePending()).toBe(false);
      expect(manager.getSearchQuery()).toBe("");

      // Fast-forward past original debounce time
      vi.advanceTimersByTime(200);
      expect(onSearch).not.toHaveBeenCalled();
      expect(onClearSearch).toHaveBeenCalledTimes(1);
    });

    it("cancels pending debounced search on clearSearch", () => {
      const onSearch = vi.fn();
      const onClearSearch = vi.fn();
      const manager = new AuditSessionSearchManager({
        onSearch,
        onClearSearch,
        debounceMs: 200,
      });

      manager.open();
      manager.setSearchQuery("192.168");
      expect(manager.isDebouncePending()).toBe(true);

      manager.clearSearch();
      expect(manager.isDebouncePending()).toBe(false);
      expect(manager.getSearchQuery()).toBe("");

      vi.advanceTimersByTime(300);
      expect(onSearch).not.toHaveBeenCalled();
      expect(onClearSearch).toHaveBeenCalledTimes(1);
    });

    it("discards late or out-of-order remote results via generation scoping", () => {
      const manager = new AuditSessionSearchManager();
      manager.open();

      manager.setSearchQuery("query-1");
      const gen1 = manager.getSearchGeneration();

      manager.setSearchQuery("query-2");
      const gen2 = manager.getSearchGeneration();
      expect(gen2).toBeGreaterThan(gen1);

      const mockItem1: FilesystemClosedSession = {
        sessionId: "s1",
        sourceIp: "1.1.1.1",
        closedAt: "2026-09-17T00:00:00Z",
        cwdState: { path: "/", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
      };

      const mockItem2: FilesystemClosedSession = {
        sessionId: "s2",
        sourceIp: "2.2.2.2",
        closedAt: "2026-09-17T00:00:00Z",
        cwdState: { path: "/var", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/var"], homeOnly: false, eventCount: 2 },
      };

      // Stale response for gen1 arrives AFTER query 2
      const acceptedGen1 = manager.setRemoteResults({ items: [mockItem1] }, gen1);
      expect(acceptedGen1).toBe(false);
      expect(manager.getRemoteSessions()).toHaveLength(0);

      // Fresh response for gen2 arrives
      const acceptedGen2 = manager.setRemoteResults({ items: [mockItem2], nextCursor: "cur-2" }, gen2);
      expect(acceptedGen2).toBe(true);
      expect(manager.getRemoteSessions()).toEqual([mockItem2]);
      expect(manager.getRemoteCursor()).toBe("cur-2");
      expect(manager.getHasMoreRemote()).toBe(true);
    });

    it("rejects remote results if closed while request was in-flight", () => {
      const manager = new AuditSessionSearchManager();
      manager.open();
      manager.setSearchQuery("query");
      const gen = manager.getSearchGeneration();

      manager.close("outside");

      const mockItem: FilesystemClosedSession = {
        sessionId: "s1",
        sourceIp: "1.1.1.1",
        closedAt: "2026-09-17T00:00:00Z",
        cwdState: { path: "/", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
      };

      const accepted = manager.setRemoteResults({ items: [mockItem] }, gen);
      expect(accepted).toBe(false);
      expect(manager.getRemoteSessions()).toHaveLength(0);
    });

    it("appends unique remote results and maintains pagination cursor", () => {
      const manager = new AuditSessionSearchManager();
      manager.open();
      manager.setSearchQuery("query");
      const gen = manager.getSearchGeneration();

      const item1: FilesystemClosedSession = {
        sessionId: "s1",
        sourceIp: "1.1.1.1",
        closedAt: "2026-09-17T00:00:00Z",
        cwdState: { path: "/", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/"], homeOnly: true, eventCount: 1 },
      };
      const item2: FilesystemClosedSession = {
        sessionId: "s2",
        sourceIp: "2.2.2.2",
        closedAt: "2026-09-17T00:00:00Z",
        cwdState: { path: "/tmp", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/tmp"], homeOnly: true, eventCount: 1 },
      };

      manager.setRemoteResults({ items: [item1], nextCursor: "page-2" }, gen);
      expect(manager.getRemoteSessions()).toHaveLength(1);

      // Append page 2 with duplicate item1 and new item2
      manager.appendRemoteResults({ items: [item1, item2], nextCursor: null }, gen);
      expect(manager.getRemoteSessions()).toHaveLength(2);
      expect(manager.getRemoteSessions().map((s) => s.sessionId)).toEqual(["s1", "s2"]);
      expect(manager.getRemoteCursor()).toBeNull();
      expect(manager.getHasMoreRemote()).toBe(false);
    });
  });

  describe("ARIA ownership and markup structure (FA-007)", () => {
    it("renders ComboboxPopover with role='dialog' and aria-modal='false' instead of role='listbox'", () => {
      const html = renderToStaticMarkup(
        createElement(
          ComboboxPopover,
          {
            isOpen: true,
            onClose: () => {},
            ariaLabel: "Test Selector",
          },
          createElement("div", { id: "test-listbox", role: "listbox" }, "options"),
        ),
      );

      expect(html).toContain('role="dialog"');
      expect(html).toContain('aria-modal="false"');
      expect(html).toContain('aria-label="Test Selector"');
      // Outer dialog wrapper must not have role="listbox"
      expect(html).not.toMatch(/<div[^>]*class="[^"]*rounded-xl[^"]*"[^>]*role="listbox"/);
    });

    it("renders AuditSessionSelect trigger as combobox pointing to listbox with roving focus", () => {
      const html = renderToStaticMarkup(
        createElement(AuditSessionSelect, {
          sessions: [],
          recentClosedSessions: [],
          selectedSessionId: null,
          onSelectSession: () => {},
        }),
      );

      // Trigger must have role="combobox", aria-haspopup="listbox", aria-expanded="false"
      expect(html).toContain('role="combobox"');
      expect(html).toContain('aria-haspopup="listbox"');
      expect(html).toContain('aria-expanded="false"');
      // aria-controls must match the listbox ID pattern
      expect(html).toMatch(/aria-controls="[^"]*-listbox"/);
      // Trigger must not claim aria-activedescendant when using roving DOM focus
      expect(html).not.toContain("aria-activedescendant");
    });

    it("renders AuditFilterControls trigger as combobox pointing to path listbox", () => {
      const html = renderToStaticMarkup(
        createElement(AuditFilterControls, {
          hideHomeOnly: false,
          onToggleHideHomeOnly: () => {},
          targetPath: null,
          onSelectTargetPath: () => {},
          distinctPaths: [],
          homeOnlyCount: 0,
          filteredCount: 0,
          totalCount: 0,
          onResetFilters: () => {},
        }),
      );

      expect(html).toContain('role="combobox"');
      expect(html).toContain('aria-haspopup="listbox"');
      expect(html).toContain('aria-expanded="false"');
      expect(html).toMatch(/aria-controls="[^"]*-listbox"/);
      expect(html).not.toContain("aria-activedescendant");
    });

    it("keeps searchbox and auxiliary buttons outside role='listbox'", () => {
      // Render ComboboxSearchInput and listbox side by side inside ComboboxPopover
      const html = renderToStaticMarkup(
        createElement(
          ComboboxPopover,
          {
            isOpen: true,
            onClose: () => {},
            ariaLabel: "Session Selector",
          },
          createElement(ComboboxSearchInput, {
            inputRef: { current: null },
            value: "test",
            onChange: () => {},
            onClear: () => {},
            onKeyDown: () => {},
            ariaControls: "session-listbox",
          }),
          createElement(
            "div",
            { role: "listbox", id: "session-listbox" },
            createElement("button", { role: "option", id: "opt-1", "aria-selected": true }, "Option 1"),
          ),
          createElement("button", { type: "button" }, "Load more"),
        ),
      );

      // ComboboxSearchInput has role="searchbox" outside listbox
      expect(html).toContain('role="searchbox"');
      expect(html).toContain('role="listbox"');
      expect(html).toContain('role="option"');
      expect(html).toContain("Load more");

      // The searchbox is NOT nested within role="listbox"
      const listboxStart = html.indexOf('role="listbox"');
      const searchboxStart = html.indexOf('role="searchbox"');
      expect(searchboxStart).toBeLessThan(listboxStart);

      // The action button is NOT nested within role="listbox"
      const listboxEnd = html.indexOf("</div>", listboxStart);
      const buttonStart = html.indexOf("Load more");
      expect(buttonStart).toBeGreaterThan(listboxEnd);
    });
  });
});

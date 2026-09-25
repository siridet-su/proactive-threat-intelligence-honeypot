// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
MotionGlobalConfig.skipAnimations = true;

import { AuditFilterControls } from "../src/components/filesystem/AuditFilterControls";
import { AuditSessionSelect } from "../src/components/filesystem/AuditSessionSelect";
import {
  AuditSessionSearchManager,
} from "../src/components/filesystem/auditSessionSearchManager";
import {
  calculateNextComboboxIndex,
  ComboboxPopover,
  determineFocusTarget,
  findTypeaheadIndex,
  isMeaningfulFocusTarget,
} from "../src/components/filesystem/ComboboxPopover";
import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "../src/lib/dashboardTypes";

function fireKeyDown(element: Element, key: string, extra: Partial<KeyboardEventInit> = {}) {
  element.dispatchEvent(
    new KeyboardEvent("keydown", {
      key,
      bubbles: true,
      cancelable: true,
      ...extra,
    }),
  );
}

function fireClick(element: Element) {
  element.dispatchEvent(
    new MouseEvent("click", {
      bubbles: true,
      cancelable: true,
    }),
  );
}

function firePointerDown(element: Element) {
  element.dispatchEvent(
    new PointerEvent("pointerdown", {
      bubbles: true,
      cancelable: true,
    }),
  );
}

function fireInputChange(input: HTMLInputElement, value: string) {
  const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  )?.set;
  if (nativeInputValueSetter) {
    nativeInputValueSetter.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

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
      expect(findTypeaheadIndex(sessionItems, getIp, "192", 0)).toBe(2);
      expect(findTypeaheadIndex(sessionItems, getIp, "192", 2)).toBe(4);
    });

    it("wraps around to the beginning when no forward match exists", () => {
      expect(findTypeaheadIndex(sessionItems, getIp, "10.", 4)).toBe(0);
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

  describe("isMeaningfulFocusTarget (FA-007)", () => {
    it("returns false for null, document.body, and document.documentElement", () => {
      expect(isMeaningfulFocusTarget(null)).toBe(false);
      expect(isMeaningfulFocusTarget(document.body)).toBe(false);
      expect(isMeaningfulFocusTarget(document.documentElement)).toBe(false);
    });

    it("returns false for disconnected DOM elements", () => {
      const detachedBtn = document.createElement("button");
      expect(isMeaningfulFocusTarget(detachedBtn)).toBe(false);
    });

    it("returns true for connected focusable controls", () => {
      const btn = document.createElement("button");
      const input = document.createElement("input");
      document.body.appendChild(btn);
      document.body.appendChild(input);
      try {
        expect(isMeaningfulFocusTarget(btn)).toBe(true);
        expect(isMeaningfulFocusTarget(input)).toBe(true);
      } finally {
        btn.remove();
        input.remove();
      }
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
      const closed1 = manager.close("escape");
      expect(closed1).toBe(true);
      expect(manager.getIsOpen()).toBe(false);
      expect(onClearSearch).toHaveBeenCalledTimes(1);

      // Repeated close when already closed does not re-fire onClearSearch (idempotent!)
      const closedAgain = manager.close("escape");
      expect(closedAgain).toBe(false);
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

      manager.appendRemoteResults({ items: [item1, item2], nextCursor: null }, gen);
      expect(manager.getRemoteSessions()).toHaveLength(2);
      expect(manager.getRemoteSessions().map((s) => s.sessionId)).toEqual(["s1", "s2"]);
      expect(manager.getRemoteCursor()).toBeNull();
      expect(manager.getHasMoreRemote()).toBe(false);
    });
  });

  describe("Real DOM Component Interaction Tests (FA-007)", () => {
    let container: HTMLDivElement;
    let root: Root;

    const mockActiveSessions: FilesystemTopologySession[] = [
      {
        sessionId: "sess-active-1",
        sourceIp: "10.0.0.1",
        cwdState: { path: "/var/log", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/var/log"], homeOnly: false, eventCount: 2 },
      },
      {
        sessionId: "sess-active-2",
        sourceIp: "10.0.0.2",
        cwdState: { path: "/etc", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/etc"], homeOnly: false, eventCount: 3 },
      },
    ];

    const mockClosedSessions: FilesystemClosedSession[] = [
      {
        sessionId: "sess-closed-1",
        sourceIp: "192.168.1.1",
        closedAt: "2026-09-17T01:00:00Z",
        cwdState: { path: "/home/user", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" },
        auditSummary: { visitedPaths: ["/home/user"], homeOnly: true, eventCount: 1 },
      },
    ];

    const mockDistinctPaths = [
      { path: "/bin", sessionCount: 5 },
      { path: "/etc", sessionCount: 3 },
      { path: "/var/log", sessionCount: 2 },
    ];

    beforeEach(() => {
      if (!window.HTMLElement.prototype.scrollIntoView) {
        window.HTMLElement.prototype.scrollIntoView = () => {};
      }
      container = document.createElement("div");
      document.body.appendChild(container);
      root = createRoot(container);
    });

    afterEach(() => {
      act(() => {
        root.unmount();
      });
      container.remove();
    });

    it("AuditSessionSelect: separates session identity from bounded time, event, and path metadata", async () => {
      const retained: FilesystemClosedSession = {
        sessionId: "abcdef1234567890",
        sourceIp: "203.0.113.42",
        lifecycle: {
          startedAt: "2026-09-24T02:50:00Z",
          closedAt: "2026-09-24T02:52:17Z",
        },
        cwdState: {
          path: "/this/is/a/very/long/verified/current/working/directory",
          status: "confirmed",
          observedAt: "2026-09-24T02:52:00Z",
        },
        auditSummary: {
          visitedPaths: ["/this/is/a/very/long/verified/current/working/directory"],
          homeOnly: false,
          eventCount: 12,
        },
      };

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [],
            recentClosedSessions: [retained],
            selectedSessionId: retained.sessionId,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      expect(trigger.getAttribute("title")).toBeNull();
      await act(async () => fireClick(trigger));

      const option = container.querySelector('button[role="option"]') as HTMLButtonElement;
      expect(option.getAttribute("aria-label")).toContain("session abcdef1234567890");
      expect(option.getAttribute("aria-label")).toContain("12 events");
      expect(option.getAttribute("aria-label")).toContain(retained.cwdState?.path);
      expect(option.textContent).not.toContain("abcdef1234567890");
      expect(option.textContent).not.toContain("SID");
      expect(option.textContent).toContain("Closed 24 Sept 2026, 02:52:17 UTC");
      expect(option.textContent).toContain("12 events");
      expect(option.textContent).toContain("/this/is/a/very/lon…/directory");
      expect(option.querySelector("[title]")).toBeNull();
      expect(option.querySelector("[data-keyboard-tooltip]")).toBeNull();

      const pathBadge = option.querySelector("svg")?.parentElement;
      expect(pathBadge?.className).toContain("min-w-0");
      expect(pathBadge?.querySelector(".truncate")).not.toBeNull();
    });

    it("AuditSessionSelect: ArrowDown while closed opens and focuses the first option", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      expect(trigger).not.toBeNull();
      expect(trigger.getAttribute("aria-expanded")).toBe("false");

      trigger.focus();
      expect(document.activeElement).toBe(trigger);

      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("true");
      const firstOption = container.querySelector('button[role="option"]') as HTMLButtonElement;
      expect(firstOption).not.toBeNull();
      expect(document.activeElement).toBe(firstOption);
    });

    it("AuditSessionSelect: ArrowUp while closed opens and focuses the last option", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "ArrowUp");
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("true");
      const options = container.querySelectorAll('button[role="option"]');
      expect(options.length).toBe(3); // 2 active + 1 closed
      const lastOption = options[options.length - 1];
      expect(document.activeElement).toBe(lastOption);
    });

    it("AuditSessionSelect: Enter/Space opens and focuses the search input", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "Enter");
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("true");
      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      expect(searchInput).not.toBeNull();
      expect(document.activeElement).toBe(searchInput);
    });

    it("AuditSessionSelect: Escape closes, restores trigger focus, and calls cleanup exactly once", async () => {
      const onClearSearch = vi.fn();
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            onClearSearch,
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });
      expect(trigger.getAttribute("aria-expanded")).toBe("true");

      const activeOption = document.activeElement as HTMLElement;
      expect(activeOption.getAttribute("role")).toBe("option");

      await act(async () => {
        fireKeyDown(activeOption, "Escape");
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(document.activeElement).toBe(trigger);
      expect(onClearSearch).toHaveBeenCalledTimes(1);
    });

    it("AuditSessionSelect: Mouse option selection closes and restores focus", async () => {
      const onSelectSession = vi.fn();
      const onClearSearch = vi.fn();
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession,
            onClearSearch,
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireClick(trigger);
      });
      expect(trigger.getAttribute("aria-expanded")).toBe("true");

      const options = container.querySelectorAll('button[role="option"]');
      const secondOption = options[1] as HTMLButtonElement;

      await act(async () => {
        fireClick(secondOption);
      });

      expect(onSelectSession).toHaveBeenCalledTimes(1);
      expect(onSelectSession).toHaveBeenCalledWith("sess-active-2", mockActiveSessions[1]);
      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(document.activeElement).toBe(trigger);
      expect(onClearSearch).toHaveBeenCalledTimes(1);
    });

    it("AuditSessionSelect: Keyboard option selection closes and restores focus", async () => {
      const onSelectSession = vi.fn();
      const onClearSearch = vi.fn();
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession,
            onClearSearch,
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      const firstOption = document.activeElement as HTMLButtonElement;
      expect(firstOption.getAttribute("role")).toBe("option");

      await act(async () => {
        fireKeyDown(firstOption, "Enter");
      });

      expect(onSelectSession).toHaveBeenCalledTimes(1);
      expect(onSelectSession).toHaveBeenCalledWith("sess-active-1", mockActiveSessions[0]);
      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(document.activeElement).toBe(trigger);
      expect(onClearSearch).toHaveBeenCalledTimes(1);
    });

    it("AuditSessionSelect: Search input ArrowDown enters option list and ArrowUp returns to input", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "Enter");
      });

      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      expect(document.activeElement).toBe(searchInput);

      // ArrowDown enters the option list at index 0
      await act(async () => {
        fireKeyDown(searchInput, "ArrowDown");
      });
      const firstOption = container.querySelectorAll('button[role="option"]')[0];
      expect(document.activeElement).toBe(firstOption);

      // ArrowUp from index 0 returns focus to search input
      await act(async () => {
        fireKeyDown(firstOption, "ArrowUp");
      });
      expect(document.activeElement).toBe(searchInput);
    });

    it("AuditSessionSelect: Outside pointer close performs cleanup once without stealing focus", async () => {
      const onClearSearch = vi.fn();
      const outsideBtn = document.createElement("button");
      outsideBtn.id = "outside-button";
      document.body.appendChild(outsideBtn);

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            onClearSearch,
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "Enter");
      });
      expect(trigger.getAttribute("aria-expanded")).toBe("true");

      outsideBtn.focus();
      expect(document.activeElement).toBe(outsideBtn);

      await act(async () => {
        firePointerDown(outsideBtn);
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(onClearSearch).toHaveBeenCalledTimes(1);
      // Focus must NOT be stolen back to trigger on outside click!
      expect(document.activeElement).toBe(outsideBtn);

      outsideBtn.remove();
    });

    it("AuditSessionSelect: Empty/loading/error states preserve a valid ARIA controlled element", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            status: "error",
            errorMessage: "Failed to reach backend",
            onRetry: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireClick(trigger);
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("true");
      const listboxId = trigger.getAttribute("aria-controls");
      expect(listboxId).toBeTruthy();

      const listbox = container.querySelector(`#${listboxId}`);
      expect(listbox).not.toBeNull();
      expect(listbox?.getAttribute("role")).toBe("listbox");

      // Search, retry button, and error text must be outside listbox
      const searchbox = container.querySelector('input[role="searchbox"]');
      const retryBtn = container.querySelector('button:not([role])');

      expect(searchbox).not.toBeNull();
      expect(listbox?.contains(searchbox)).toBe(false);

      expect(retryBtn).not.toBeNull();
      expect(listbox?.contains(retryBtn)).toBe(false);
    });

    it("AuditFilterControls: ArrowDown while closed opens and focuses 'All paths'", async () => {
      const onSelectTargetPath = vi.fn();
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath,
            distinctPaths: mockDistinctPaths,
            homeOnlyCount: 1,
            filteredCount: 5,
            totalCount: 10,
            onResetFilters: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      expect(trigger).not.toBeNull();
      expect(trigger.getAttribute("aria-expanded")).toBe("false");

      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("true");
      const firstOption = container.querySelector('button[role="option"]') as HTMLButtonElement;
      expect(document.activeElement).toBe(firstOption);
      expect(firstOption.textContent).toContain("All paths");
    });

    it("AuditFilterControls: Escape closes, restores trigger focus", async () => {
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            distinctPaths: mockDistinctPaths,
            homeOnlyCount: 1,
            filteredCount: 5,
            totalCount: 10,
            onResetFilters: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });
      expect(trigger.getAttribute("aria-expanded")).toBe("true");

      const activeOption = document.activeElement as HTMLElement;
      await act(async () => {
        fireKeyDown(activeOption, "Escape");
      });

      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(document.activeElement).toBe(trigger);
    });

    it("AuditFilterControls: Option selection closes and restores trigger focus", async () => {
      const onSelectTargetPath = vi.fn();
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath,
            distinctPaths: mockDistinctPaths,
            homeOnlyCount: 1,
            filteredCount: 5,
            totalCount: 10,
            onResetFilters: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      const options = container.querySelectorAll('button[role="option"]');
      const binOption = options[1] as HTMLButtonElement; // /bin path option

      await act(async () => {
        fireClick(binOption);
      });

      expect(onSelectTargetPath).toHaveBeenCalledWith("/bin");
      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(document.activeElement).toBe(trigger);
    });

    it("AuditSessionSelect: Clear-search focus does not retain a stale active option", async () => {
      const onSelectSession = vi.fn();
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession,
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "Enter");
      });

      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      expect(document.activeElement).toBe(searchInput);

      // Navigate down to option 0
      await act(async () => {
        fireKeyDown(searchInput, "ArrowDown");
      });
      const firstOption = container.querySelectorAll('button[role="option"]')[0];
      expect(document.activeElement).toBe(firstOption);

      // Return focus to search input
      await act(async () => {
        searchInput.focus();
      });
      expect(document.activeElement).toBe(searchInput);

      // Press Enter in search input - must NOT select option 0!
      await act(async () => {
        fireKeyDown(searchInput, "Enter");
      });
      expect(onSelectSession).not.toHaveBeenCalled();
      expect(trigger.getAttribute("aria-expanded")).toBe("true");
    });

    it("AuditSessionSelect: Filtering/removing the focused option produces deterministic valid focus", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });
      const options = container.querySelectorAll('button[role="option"]');
      expect(document.activeElement).toBe(options[0]);

      // Move down to option 2 (sess-closed-1)
      await act(async () => {
        fireKeyDown(options[0], "ArrowDown");
      });
      const secondOption = container.querySelectorAll('button[role="option"]')[1];
      await act(async () => {
        fireKeyDown(secondOption, "ArrowDown");
      });
      const thirdOption = container.querySelectorAll('button[role="option"]')[2];
      expect(document.activeElement).toBe(thirdOption);

      // Now filter list to 0 matches by searching "nomatch"
      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      await act(async () => {
        fireInputChange(searchInput, "nomatch_anything_here");
      });

      // Focus must deterministically move to search input
      expect(document.activeElement).toBe(searchInput);
    });

    it("AuditSessionSelect: Pending debounce never fires after clear or close", async () => {
      vi.useFakeTimers();
      const onSearch = vi.fn();
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            onSearch,
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();

      await act(async () => {
        fireKeyDown(trigger, "Enter");
      });

      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      await act(async () => {
        fireInputChange(searchInput, "pending-query");
      });

      // Close popover via Escape before debounce timer expires (250ms)
      await act(async () => {
        fireKeyDown(searchInput, "Escape");
      });

      // Advance timers past debounce
      act(() => {
        vi.advanceTimersByTime(500);
      });

      expect(onSearch).not.toHaveBeenCalled();
      vi.useRealTimers();
    });

    it("AuditSessionSelect: onClearSearch is called exactly once for every logical close path", async () => {
      const onClearSearch = vi.fn();
      const props = {
        sessions: mockActiveSessions,
        recentClosedSessions: mockClosedSessions,
        selectedSessionId: null,
        onSelectSession: vi.fn(),
        onClearSearch,
      };

      await act(async () => {
        root.render(createElement(AuditSessionSelect, props));
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;

      // 1. Option click
      await act(async () => {
        fireClick(trigger);
      });
      const opt1 = container.querySelector('button[role="option"]') as HTMLButtonElement;
      await act(async () => {
        fireClick(opt1);
      });
      expect(onClearSearch).toHaveBeenCalledTimes(1);

      // 2. Keyboard Enter on option
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });
      const opt2 = document.activeElement as HTMLButtonElement;
      await act(async () => {
        fireKeyDown(opt2, "Enter");
      });
      expect(onClearSearch).toHaveBeenCalledTimes(2);

      // 3. Space on option
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });
      const opt3 = document.activeElement as HTMLButtonElement;
      await act(async () => {
        fireKeyDown(opt3, " ");
      });
      expect(onClearSearch).toHaveBeenCalledTimes(3);

      // 4. Escape on option
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });
      const opt4 = document.activeElement as HTMLButtonElement;
      await act(async () => {
        fireKeyDown(opt4, "Escape");
      });
      expect(onClearSearch).toHaveBeenCalledTimes(4);

      // 5. Escape on search input
      await act(async () => {
        fireKeyDown(trigger, "Enter");
      });
      const input = document.activeElement as HTMLInputElement;
      await act(async () => {
        fireKeyDown(input, "Escape");
      });
      expect(onClearSearch).toHaveBeenCalledTimes(5);

      // 6. Trigger toggle
      await act(async () => {
        fireClick(trigger);
      });
      expect(trigger.getAttribute("aria-expanded")).toBe("true");
      await act(async () => {
        fireClick(trigger);
      });
      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(onClearSearch).toHaveBeenCalledTimes(6);
    });

    it("AuditSessionSelect: Auxiliary controls (search, retry, reset, load-more) are strictly outside listbox", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: mockActiveSessions,
            recentClosedSessions: mockClosedSessions,
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            hasActiveFilters: true,
            onResetFilters: vi.fn(),
            status: "error",
            errorMessage: "Test error message",
            onRetry: vi.fn(),
            directoryHasMore: true,
            onLoadMoreDirectory: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      await act(async () => {
        fireClick(trigger);
      });

      const listboxId = trigger.getAttribute("aria-controls");
      const listbox = container.querySelector(`#${listboxId}`);
      expect(listbox).not.toBeNull();

      // Ensure search input is outside listbox
      const searchbox = container.querySelector('input[role="searchbox"]');
      expect(searchbox).not.toBeNull();
      expect(listbox?.contains(searchbox)).toBe(false);

      // Ensure retry button is outside listbox
      const buttons = Array.from(container.querySelectorAll("button"));
      const retryBtn = buttons.find((b) => b.textContent?.includes("Retry"));
      expect(retryBtn).toBeDefined();
      expect(listbox?.contains(retryBtn!)).toBe(false);

      // Ensure load more button is outside listbox
      const loadMoreBtn = buttons.find((b) => b.textContent?.includes("Load older closed sessions"));
      expect(loadMoreBtn).toBeDefined();
      expect(listbox?.contains(loadMoreBtn!)).toBe(false);

      // Ensure listbox only contains role="group" and role="option" children
      const listboxChildren = Array.from(listbox?.children ?? []);
      for (const child of listboxChildren) {
        const role = child.getAttribute("role");
        expect(["group", "option"]).toContain(role);
      }

      // Re-render in empty state with active filters to test reset button
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            hasActiveFilters: true,
            onResetFilters: vi.fn(),
          }),
        );
      });

      const updatedButtons = Array.from(container.querySelectorAll("button"));
      const resetBtn = updatedButtons.find((b) => b.textContent?.includes("Reset audit filters"));
      expect(resetBtn).toBeDefined();
      expect(listbox?.contains(resetBtn!)).toBe(false);
    });

    it("AuditSessionSelect: Standalone fallback HTTP search race and unmount cancellation", async () => {
      let fetchCallCount = 0;
      let abortedCallCount = 0;

      const originalFetch = globalThis.fetch;
      const mockFetch = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
        fetchCallCount++;
        const signal = init?.signal;
        return new Promise((_resolve, reject) => {
          signal?.addEventListener("abort", () => {
            abortedCallCount++;
            const abortErr = new Error("The operation was aborted.");
            abortErr.name = "AbortError";
            reject(abortErr);
          });
        });
      });

      globalThis.fetch = mockFetch;

      try {
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
            }),
          );
        });

        const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
        await act(async () => {
          fireClick(trigger);
        });

        const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;

        vi.useFakeTimers();
        await act(async () => {
          fireInputChange(searchInput, "query1");
        });
        await act(async () => {
          vi.advanceTimersByTime(260);
        });
        expect(fetchCallCount).toBe(1);

        // Type "query2" before query1 completes -> aborts query1
        await act(async () => {
          fireInputChange(searchInput, "query2");
        });
        expect(abortedCallCount).toBe(1);

        await act(async () => {
          vi.advanceTimersByTime(260);
        });
        expect(fetchCallCount).toBe(2);

        // Close popover -> aborts query2
        await act(async () => {
          fireKeyDown(searchInput, "Escape");
        });
        expect(abortedCallCount).toBe(2);

        vi.useRealTimers();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("AuditSessionSelect: Full standalone pagination lifecycle (page 1 -> page 2 -> completion)", async () => {
      vi.useFakeTimers();
      const originalFetch = globalThis.fetch;

      const page1Response = {
        items: [
          { sessionId: "sess-p1-1", sourceIp: "10.0.1.1", closedAt: "2026-09-17T00:00:00Z" },
          { sessionId: "sess-p1-2", sourceIp: "10.0.1.2", closedAt: "2026-09-17T00:01:00Z" },
        ],
        nextCursor: "cursor-page-1",
        totalItems: 3,
      };

      const page2Response = {
        items: [
          { sessionId: "sess-p1-2", sourceIp: "10.0.1.2", closedAt: "2026-09-17T00:01:00Z" },
          { sessionId: "sess-p2-1", sourceIp: "10.0.2.1", closedAt: "2026-09-17T00:02:00Z" },
        ],
        nextCursor: null,
        totalItems: 3,
      };

      let resolvePage1!: (res: Response) => void;
      const page1Promise = new Promise<Response>((res) => {
        resolvePage1 = res;
      });

      let resolvePage2!: (res: Response) => void;
      const page2Promise = new Promise<Response>((res) => {
        resolvePage2 = res;
      });

      const fetchUrls: string[] = [];
      const mockFetch = vi.fn().mockImplementation((url: string) => {
        fetchUrls.push(url);
        if (url.includes("cursor=cursor-page-1")) {
          return page2Promise;
        }
        return page1Promise;
      });

      globalThis.fetch = mockFetch;

      try {
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
            }),
          );
        });

        const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
        await act(async () => {
          fireClick(trigger);
        });

        const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;

        // 1. Standalone query begins
        await act(async () => {
          fireInputChange(searchInput, "web-attack");
        });

        // Advance debounce
        await act(async () => {
          vi.advanceTimersByTime(260);
        });

        expect(mockFetch).toHaveBeenCalledTimes(1);
        expect(fetchUrls[0]).toContain("q=web-attack");
        expect(fetchUrls[0]).not.toContain("cursor=");

        // Loading state is visible (spinner in search input and searching message)
        const searchInputWrapper = searchInput.parentElement;
        expect(searchInputWrapper?.querySelector(".animate-spin")).not.toBeNull();
        expect(container.textContent).toContain("Searching sessions…");

        // 2. Page-one response resolves
        await act(async () => {
          resolvePage1(
            new Response(JSON.stringify(page1Response), {
              status: 200,
              headers: { "Content-Type": "application/json" },
            }),
          );
        });

        // Options for page 1 are rendered
        const optionsPage1 = container.querySelectorAll('button[role="option"]');
        expect(optionsPage1.length).toBe(2);
        expect(optionsPage1[0].textContent).toContain("10.0.1.1");
        expect(optionsPage1[1].textContent).toContain("10.0.1.2");

        // "Load more matching sessions" button is rendered from nextCursor
        const buttons = Array.from(container.querySelectorAll("button"));
        const loadMoreBtn = buttons.find((b) => b.textContent?.includes("Load more matching sessions"));
        expect(loadMoreBtn).toBeDefined();

        // 3. Click Load more -> requests page 2 with expected cursor
        await act(async () => {
          fireClick(loadMoreBtn!);
        });

        expect(mockFetch).toHaveBeenCalledTimes(2);
        expect(fetchUrls[1]).toContain("cursor=cursor-page-1");

        // Loading UI reflects loading state during page 2
        expect(loadMoreBtn?.textContent).toContain("Loading search results…");
        expect(loadMoreBtn?.getAttribute("disabled")).not.toBeNull();

        // 4. Page-two response resolves
        await act(async () => {
          resolvePage2(
            new Response(JSON.stringify(page2Response), {
              status: 200,
              headers: { "Content-Type": "application/json" },
            }),
          );
        });

        // Page-two appends unique sessions (deduplicating sess-p1-2 -> 3 total items)
        const finalOptions = container.querySelectorAll('button[role="option"]');
        expect(finalOptions.length).toBe(3);
        expect(finalOptions[2].textContent).toContain("10.0.2.1");

        // Page-two completion removes Load more button and displays completion banner
        const updatedButtons = Array.from(container.querySelectorAll("button"));
        const remainingLoadMore = updatedButtons.find((b) => b.textContent?.includes("Load more matching sessions"));
        expect(remainingLoadMore).toBeUndefined();
        expect(container.textContent).toContain("All matching search results loaded (3)");
      } finally {
        globalThis.fetch = originalFetch;
        vi.useRealTimers();
      }
    });

    it("AuditSessionSelect: Parent-controlled mode uses parent state and performs no fallback fetch", async () => {
      vi.useFakeTimers();
      const originalFetch = globalThis.fetch;
      const mockFetch = vi.fn();
      globalThis.fetch = mockFetch;

      const onSearch = vi.fn();
      const onLoadMoreSearch = vi.fn();

      try {
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
              onSearch,
              onLoadMoreSearch,
              searchResults: [
                { sessionId: "parent-sess-1", sourceIp: "172.16.0.1", closedAt: "2026-09-17T00:00:00Z" },
              ],
              searchHasMore: true,
              searchIsLoading: false,
              searchIsComplete: false,
            }),
          );
        });

        const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
        await act(async () => {
          fireClick(trigger);
        });

        const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
        await act(async () => {
          fireInputChange(searchInput, "parent-test");
        });

        await act(async () => {
          vi.advanceTimersByTime(260);
        });

        // onSearch was called with query
        expect(onSearch).toHaveBeenCalledWith("parent-test");
        // Standalone fallback fetch was NEVER called
        expect(mockFetch).not.toHaveBeenCalled();

        // Displays parent searchResults
        const options = container.querySelectorAll('button[role="option"]');
        expect(options.length).toBe(1);
        expect(options[0].textContent).toContain("172.16.0.1");

        // Displays load more button because searchHasMore is true
        const buttons = Array.from(container.querySelectorAll("button"));
        const loadMoreBtn = buttons.find((b) => b.textContent?.includes("Load more matching sessions"));
        expect(loadMoreBtn).toBeDefined();

        // Click load more triggers onLoadMoreSearch
        await act(async () => {
          fireClick(loadMoreBtn!);
        });
        expect(onLoadMoreSearch).toHaveBeenCalledTimes(1);
        expect(mockFetch).not.toHaveBeenCalled();
      } finally {
        globalThis.fetch = originalFetch;
        vi.useRealTimers();
      }
    });

    it("AuditSessionSelect: Stale fetch ignoring AbortSignal and delayed json() cannot mutate state", async () => {
      vi.useFakeTimers();
      const originalFetch = globalThis.fetch;

      let resolveStaleFetch!: (res: Response) => void;
      const staleFetchPromise = new Promise<Response>((res) => {
        resolveStaleFetch = res;
      });

      let resolveJsonDelayed!: (val: unknown) => void;
      const jsonDelayedPromise = new Promise<unknown>((res) => {
        resolveJsonDelayed = res;
      });

      let fetchCallCount = 0;
      const mockFetch = vi.fn().mockImplementation((url: string) => {
        fetchCallCount++;
        if (url.includes("q=stale-query")) {
          // Intentionally ignore AbortSignal to verify generation guard
          return staleFetchPromise;
        }
        if (url.includes("q=delayed-json")) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => jsonDelayedPromise,
          } as unknown as Response);
        }
        return Promise.resolve(new Response(JSON.stringify({ items: [], nextCursor: null }), { status: 200 }));
      });

      globalThis.fetch = mockFetch;

      try {
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
            }),
          );
        });

        const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
        await act(async () => {
          fireClick(trigger);
        });

        const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;

        // Start stale-query
        await act(async () => {
          fireInputChange(searchInput, "stale-query");
        });
        await act(async () => {
          vi.advanceTimersByTime(260);
        });
        expect(fetchCallCount).toBe(1);

        // Before stale-query finishes, start delayed-json query
        await act(async () => {
          fireInputChange(searchInput, "delayed-json");
        });
        await act(async () => {
          vi.advanceTimersByTime(260);
        });
        expect(fetchCallCount).toBe(2);

        // Now resolve the stale fetch (ignoring abort signal)
        await act(async () => {
          resolveStaleFetch(
            new Response(
              JSON.stringify({
                items: [{ sessionId: "stale-sess", sourceIp: "9.9.9.9", closedAt: "2026-09-17T00:00:00Z" }],
                nextCursor: null,
              }),
              { status: 200 },
            ),
          );
        });

        // Stale items MUST NOT be rendered
        expect(container.textContent).not.toContain("9.9.9.9");

        // Before delayed-json finishes parsing, user switches filter (incrementing generation)
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
              hideHomeOnly: true, // filter changed
            }),
          );
        });

        // Now resolve the delayed json parse
        await act(async () => {
          resolveJsonDelayed({
            items: [{ sessionId: "delayed-sess", sourceIp: "8.8.8.8", closedAt: "2026-09-17T00:00:00Z" }],
            nextCursor: null,
          });
        });

        // Delayed items MUST NOT be rendered due to generation guard
        expect(container.textContent).not.toContain("8.8.8.8");
      } finally {
        globalThis.fetch = originalFetch;
        vi.useRealTimers();
      }
    });

    it("AuditSessionSelect: Query change before page two completes cannot append results from prior scope", async () => {
      vi.useFakeTimers();
      const originalFetch = globalThis.fetch;

      let resolvePage2Stale!: (res: Response) => void;
      const page2StalePromise = new Promise<Response>((res) => {
        resolvePage2Stale = res;
      });

      const mockFetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes("cursor=cursor-q1")) {
          // Page 2 in-flight; ignores abort
          return page2StalePromise;
        }
        if (url.includes("q=q1")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                items: [{ sessionId: "q1-p1", sourceIp: "10.1.1.1", closedAt: "2026-09-17T00:00:00Z" }],
                nextCursor: "cursor-q1",
              }),
              { status: 200 },
            ),
          );
        }
        if (url.includes("q=q2")) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                items: [{ sessionId: "q2-p1", sourceIp: "10.2.2.2", closedAt: "2026-09-17T00:00:00Z" }],
                nextCursor: null,
              }),
              { status: 200 },
            ),
          );
        }
        return Promise.resolve(new Response(JSON.stringify({ items: [] }), { status: 200 }));
      });

      globalThis.fetch = mockFetch;

      try {
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
            }),
          );
        });

        const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
        await act(async () => {
          fireClick(trigger);
        });

        const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;

        // Query 1 page one
        await act(async () => {
          fireInputChange(searchInput, "q1");
        });
        await act(async () => {
          vi.advanceTimersByTime(260);
        });

        expect(container.textContent).toContain("10.1.1.1");
        const loadMoreBtn = Array.from(container.querySelectorAll("button")).find((b) =>
          b.textContent?.includes("Load more matching sessions"),
        );
        expect(loadMoreBtn).toBeDefined();

        // Request page 2
        await act(async () => {
          fireClick(loadMoreBtn!);
        });

        // Before page 2 returns, change query to "q2"
        await act(async () => {
          fireInputChange(searchInput, "q2");
        });
        await act(async () => {
          vi.advanceTimersByTime(260);
        });

        expect(container.textContent).toContain("10.2.2.2");

        // Now resolve late page 2 for q1
        await act(async () => {
          resolvePage2Stale(
            new Response(
              JSON.stringify({
                items: [{ sessionId: "q1-p2", sourceIp: "10.1.1.2", closedAt: "2026-09-17T00:00:00Z" }],
                nextCursor: null,
              }),
              { status: 200 },
            ),
          );
        });

        // Must NOT append q1 page 2 items
        expect(container.textContent).not.toContain("10.1.1.2");
        const options = container.querySelectorAll('button[role="option"]');
        expect(options.length).toBe(1);
        expect(options[0].textContent).toContain("10.2.2.2");
      } finally {
        globalThis.fetch = originalFetch;
        vi.useRealTimers();
      }
    });

    it("AuditSessionSelect: Replaces N options with N different options while focused (focus recovery by identity)", async () => {
      const sessionsA: FilesystemTopologySession[] = [
        { sessionId: "s-a1", sourceIp: "10.0.0.1", cwdState: { path: "/a1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
        { sessionId: "s-a2", sourceIp: "10.0.0.2", cwdState: { path: "/a2", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
        { sessionId: "s-a3", sourceIp: "10.0.0.3", cwdState: { path: "/a3", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
      ];

      const sessionsB: FilesystemTopologySession[] = [
        { sessionId: "s-b1", sourceIp: "10.0.0.4", cwdState: { path: "/b1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
        { sessionId: "s-b2", sourceIp: "10.0.0.5", cwdState: { path: "/b2", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
        { sessionId: "s-b3", sourceIp: "10.0.0.6", cwdState: { path: "/b3", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
      ];

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: sessionsA,
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      const options = container.querySelectorAll('button[role="option"]');
      expect(document.activeElement).toBe(options[0]);

      // Move to s-a2 (index 1)
      await act(async () => {
        fireKeyDown(options[0], "ArrowDown");
      });
      expect(document.activeElement?.textContent).toContain("10.0.0.2");

      // Replace 3 options with 3 completely different options (same length = 3!)
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: sessionsB,
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      // s-a2 is gone: activeElement MUST NOT be body; moves to searchbox fallback
      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      expect(document.activeElement).not.toBe(document.body);
      expect(document.activeElement).toBe(searchInput);
    });

    it("AuditFilterControls: Changes filtered results while preserving same item count (focus recovery by identity)", async () => {
      const distinctPathsA = [
        { path: "/dir-alpha", sessionCount: 2 },
        { path: "/dir-beta", sessionCount: 1 },
      ];

      const distinctPathsB = [
        { path: "/dir-gamma", sessionCount: 3 },
        { path: "/dir-delta", sessionCount: 4 },
      ];

      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            distinctPaths: distinctPathsA,
            homeOnlyCount: 0,
            filteredCount: 2,
            totalCount: 2,
            onResetFilters: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      // Focus is on option 0 ("All paths")
      const options = container.querySelectorAll('button[role="option"]');
      expect(document.activeElement).toBe(options[0]);

      // Move down to /dir-alpha (index 1)
      await act(async () => {
        fireKeyDown(options[0], "ArrowDown");
      });
      expect(document.activeElement?.textContent).toContain("/dir-alpha");

      // Replace distinct paths with distinctPathsB (same count: 2 paths, total options = 3)
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            distinctPaths: distinctPathsB,
            homeOnlyCount: 0,
            filteredCount: 2,
            totalCount: 2,
            onResetFilters: vi.fn(),
          }),
        );
      });

      // /dir-alpha was removed: activeElement MUST NOT be body; moves to searchbox fallback
      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      expect(document.activeElement).not.toBe(document.body);
      expect(document.activeElement).toBe(searchInput);
    });

    it("AuditSessionSelect: Reordering items preserves focus by identity rather than stale numeric index", async () => {
      const s1: FilesystemTopologySession = { sessionId: "s1", sourceIp: "10.0.0.1", cwdState: { path: "/p1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };
      const s2: FilesystemTopologySession = { sessionId: "s2", sourceIp: "10.0.0.2", cwdState: { path: "/p2", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };
      const s3: FilesystemTopologySession = { sessionId: "s3", sourceIp: "10.0.0.3", cwdState: { path: "/p3", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [s1, s2, s3],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      const options = container.querySelectorAll('button[role="option"]');
      // Navigate to s2 (currently index 1)
      await act(async () => {
        fireKeyDown(options[0], "ArrowDown");
      });
      expect(document.activeElement?.textContent).toContain("10.0.0.2");

      // Reorder sessions so s2 moves to index 0: [s2, s3, s1]
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [s2, s3, s1],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      // Focus MUST remain on s2 by identity (now at index 0, not jumping to s3 at index 1!)
      expect(document.activeElement?.textContent).toContain("10.0.0.2");
      expect(document.activeElement?.getAttribute("id")).toMatch(/-opt-0$/);
    });

    it("AuditFilterControls: Selected canvas path insertion preserves focus by identity", async () => {
      const distinctPaths = [
        { path: "/var/log", sessionCount: 2 },
        { path: "/etc", sessionCount: 1 },
      ];

      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            distinctPaths,
            homeOnlyCount: 0,
            filteredCount: 2,
            totalCount: 2,
            onResetFilters: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      const options = container.querySelectorAll('button[role="option"]');
      // Navigate down to /var/log (index 1)
      await act(async () => {
        fireKeyDown(options[0], "ArrowDown");
      });
      expect(document.activeElement?.textContent).toContain("/var/log");

      // Insert selectedCanvasPath="/tmp" -> inserts Canvas Selection at index 1, shifting /var/log to index 2
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            distinctPaths,
            homeOnlyCount: 0,
            filteredCount: 2,
            totalCount: 2,
            onResetFilters: vi.fn(),
            selectedCanvasPath: "/tmp",
          }),
        );
      });

      // Focus MUST remain on /var/log by identity (now at index 2, not stealing Canvas Selection at index 1!)
      expect(document.activeElement?.textContent).toContain("/var/log");
      expect(document.activeElement?.getAttribute("id")).toMatch(/-opt-2$/);
    });

    it("AuditSessionSelect: Moving focus to Load more and loading page two preserves focus on Load more without focus stealing", async () => {
      vi.useFakeTimers();
      let resolvePage2: (value: Response) => void = () => {};
      const page2Promise = new Promise<Response>((res) => {
        resolvePage2 = res;
      });

      const originalFetch = globalThis.fetch;
      globalThis.fetch = vi.fn().mockImplementation((url: string) => {
        if (url.includes("cursor=")) {
          return page2Promise;
        }
        return Promise.resolve(
          new Response(
            JSON.stringify({
              items: [
                { sessionId: "s-c1", sourceIp: "10.0.0.1", closedAt: "2026-09-17T00:00:00Z" },
                { sessionId: "s-c2", sourceIp: "10.0.0.2", closedAt: "2026-09-17T00:00:00Z" },
              ],
              nextCursor: "cursor-page-2",
            }),
            { status: 200 },
          ),
        );
      });

      try {
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
            }),
          );
        });

        const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
        trigger.focus();
        await act(async () => {
          fireKeyDown(trigger, "ArrowDown");
        });

        const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
        await act(async () => {
          fireInputChange(searchInput, "10.0.0");
          vi.advanceTimersByTime(250);
        });

        // Options loaded, focus option 0
        const options = container.querySelectorAll('button[role="option"]');
        expect(options.length).toBe(2);
        await act(async () => {
          fireKeyDown(searchInput, "ArrowDown");
        });
        expect(document.activeElement).toBe(options[0]);

        // User moves focus to "Load more" button
        const loadMoreBtn = Array.from(container.querySelectorAll("button")).find((b) =>
          b.textContent?.includes("Load more matching sessions"),
        ) as HTMLButtonElement;
        expect(loadMoreBtn).toBeDefined();

        await act(async () => {
          loadMoreBtn.focus();
        });
        expect(document.activeElement).toBe(loadMoreBtn);

        // User clicks Load More, triggering page 2 fetch and rerender with spinner
        await act(async () => {
          fireClick(loadMoreBtn);
        });

        // Focus MUST remain on Load more (not stolen back to option 0!)
        expect(document.activeElement).toBe(loadMoreBtn);

        // Resolve page 2
        await act(async () => {
          resolvePage2(
            new Response(
              JSON.stringify({
                items: [{ sessionId: "s-c3", sourceIp: "10.0.0.3", closedAt: "2026-09-17T00:00:00Z" }],
                nextCursor: null,
              }),
              { status: 200 },
            ),
          );
        });

        // Page 2 items added
        expect(container.textContent).toContain("10.0.0.3");
      } finally {
        globalThis.fetch = originalFetch;
        vi.useRealTimers();
      }
    });

    it("AuditSessionSelect: Moving focus to Retry or Reset does not steal focus back to options on rerender", async () => {
      const onRetry = vi.fn();

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [
              { sessionId: "s1", sourceIp: "10.0.0.1", cwdState: { path: "/p1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
            ],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            status: "error",
            errorMessage: "Network error",
            onRetry,
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      // Focus option 0
      const options = container.querySelectorAll('button[role="option"]');
      expect(document.activeElement).toBe(options[0]);

      // Focus Retry button
      const retryBtn = Array.from(container.querySelectorAll("button")).find((b) =>
        b.textContent?.includes("Retry"),
      ) as HTMLButtonElement;
      expect(retryBtn).toBeDefined();

      await act(async () => {
        retryBtn.focus();
      });
      expect(document.activeElement).toBe(retryBtn);

      // Rerender component (e.g. updating props)
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [
              { sessionId: "s1", sourceIp: "10.0.0.1", cwdState: { path: "/p1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } },
            ],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
            status: "error",
            errorMessage: "Network error",
            onRetry,
          }),
        );
      });

      // Focus must NOT be stolen back to option 0
      expect(document.activeElement).toBe(retryBtn);
    });

    it("AuditSessionSelect: Option focused through Tab or direct .focus() updates navigation key so reordering tracks the actually focused option", async () => {
      const s1: FilesystemTopologySession = { sessionId: "s1", sourceIp: "10.0.0.1", cwdState: { path: "/p1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };
      const s2: FilesystemTopologySession = { sessionId: "s2", sourceIp: "10.0.0.2", cwdState: { path: "/p2", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };
      const s3: FilesystemTopologySession = { sessionId: "s3", sourceIp: "10.0.0.3", cwdState: { path: "/p3", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [s1, s2, s3],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      const options = container.querySelectorAll('button[role="option"]');
      // First option (s1) was arrow-navigated
      expect(document.activeElement).toBe(options[0]);

      // Now user moves focus to s3 (index 2) via direct .focus() / Tab
      await act(async () => {
        (options[2] as HTMLButtonElement).focus();
      });
      expect(document.activeElement).toBe(options[2]);

      // Now reorder items so s3 moves to index 0: [s3, s1, s2]
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [s3, s1, s2],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      // Reconciliation MUST follow s3 (the actually focused option), NOT s1 (the previously arrow-navigated option)!
      expect(document.activeElement?.textContent).toContain("10.0.0.3");
      expect(document.activeElement?.getAttribute("id")).toMatch(/-opt-0$/);
    });

    it("AuditSessionSelect: External button focus is never stolen when combobox items update", async () => {
      const externalButton = document.createElement("button");
      externalButton.id = "external-test-btn";
      externalButton.textContent = "External Action";
      document.body.appendChild(externalButton);

      try {
        const s1: FilesystemTopologySession = { sessionId: "s1", sourceIp: "10.0.0.1", cwdState: { path: "/p1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };

        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [s1],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
            }),
          );
        });

        const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
        trigger.focus();
        await act(async () => {
          fireKeyDown(trigger, "ArrowDown");
        });

        const options = container.querySelectorAll('button[role="option"]');
        expect(document.activeElement).toBe(options[0]);

        // Focus external button
        await act(async () => {
          externalButton.focus();
        });
        expect(document.activeElement).toBe(externalButton);

        // Update items in combobox
        const s2: FilesystemTopologySession = { sessionId: "s2", sourceIp: "10.0.0.2", cwdState: { path: "/p2", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };
        await act(async () => {
          root.render(
            createElement(AuditSessionSelect, {
              sessions: [s2],
              recentClosedSessions: [],
              selectedSessionId: null,
              onSelectSession: vi.fn(),
            }),
          );
        });

        // External focus MUST remain intact!
        expect(document.activeElement).toBe(externalButton);
      } finally {
        externalButton.remove();
      }
    });

    it("AuditSessionSelect: Removing the genuinely focused option while no other deliberate target owns focus falls back to search input", async () => {
      const s1: FilesystemTopologySession = { sessionId: "s1", sourceIp: "10.0.0.1", cwdState: { path: "/p1", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };
      const s2: FilesystemTopologySession = { sessionId: "s2", sourceIp: "10.0.0.2", cwdState: { path: "/p2", status: "confirmed", observedAt: "2026-09-17T00:00:00Z" } };

      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [s1, s2],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      trigger.focus();
      await act(async () => {
        fireKeyDown(trigger, "ArrowDown");
      });

      const options = container.querySelectorAll('button[role="option"]');
      expect(document.activeElement).toBe(options[0]); // s1 has focus

      // Rerender with s1 removed (only s2 remains)
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [s2],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      // Focus was genuinely on s1 when it disappeared -> moves to search input fallback!
      const searchInput = container.querySelector('input[role="searchbox"]') as HTMLInputElement;
      expect(document.activeElement).not.toBe(document.body);
      expect(document.activeElement).toBe(searchInput);
    });
  });

  describe("ARIA ownership and markup structure (FA-007)", () => {
    let container: HTMLDivElement;
    let root: Root;

    beforeEach(() => {
      if (!window.HTMLElement.prototype.scrollIntoView) {
        window.HTMLElement.prototype.scrollIntoView = () => {};
      }
      container = document.createElement("div");
      document.body.appendChild(container);
      root = createRoot(container);
    });

    afterEach(() => {
      act(() => {
        root.unmount();
      });
      container.remove();
    });

    it("keeps outer ComboboxPopover container semantically neutral (no role='dialog' or 'listbox')", async () => {
      await act(async () => {
        root.render(
          createElement(
            ComboboxPopover,
            {
              id: "popover-container",
              isOpen: true,
              onClose: vi.fn(),
              triggerRef: { current: null },
              ariaLabel: "Test Selector",
            },
            createElement("div", { id: "test-listbox", role: "listbox" }, "options"),
          ),
        );
      });

      const popover = container.querySelector("#popover-container");
      expect(popover).not.toBeNull();
      // Outer wrapper must be semantically neutral
      expect(popover?.getAttribute("role")).toBeNull();
      expect(popover?.getAttribute("aria-modal")).toBeNull();
    });

    it("renders AuditSessionSelect trigger as combobox pointing to listbox with roving focus", async () => {
      await act(async () => {
        root.render(
          createElement(AuditSessionSelect, {
            sessions: [],
            recentClosedSessions: [],
            selectedSessionId: null,
            onSelectSession: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      expect(trigger).not.toBeNull();
      expect(trigger.getAttribute("aria-haspopup")).toBe("listbox");
      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(trigger.getAttribute("aria-controls")).toMatch(/-listbox$/);
      expect(trigger.getAttribute("aria-activedescendant")).toBeNull();
    });

    it("renders AuditFilterControls trigger as combobox pointing to path listbox", async () => {
      await act(async () => {
        root.render(
          createElement(AuditFilterControls, {
            hideHomeOnly: false,
            onToggleHideHomeOnly: vi.fn(),
            targetPath: null,
            onSelectTargetPath: vi.fn(),
            distinctPaths: [],
            homeOnlyCount: 0,
            filteredCount: 0,
            totalCount: 0,
            onResetFilters: vi.fn(),
          }),
        );
      });

      const trigger = container.querySelector('button[role="combobox"]') as HTMLButtonElement;
      expect(trigger).not.toBeNull();
      expect(trigger.getAttribute("aria-haspopup")).toBe("listbox");
      expect(trigger.getAttribute("aria-expanded")).toBe("false");
      expect(trigger.getAttribute("aria-controls")).toMatch(/-listbox$/);
      expect(trigger.getAttribute("aria-activedescendant")).toBeNull();
    });
  });
});

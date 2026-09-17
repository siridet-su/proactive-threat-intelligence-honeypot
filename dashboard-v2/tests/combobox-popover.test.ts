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

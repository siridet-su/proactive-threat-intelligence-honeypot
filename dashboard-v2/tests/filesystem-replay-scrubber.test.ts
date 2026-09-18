// @vitest-environment happy-dom
import { act, createElement, type ComponentProps } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
MotionGlobalConfig.skipAnimations = true;

vi.mock("server-only", () => ({}));

import { CwdRouteHistory } from "../src/components/filesystem/CwdRouteHistory";
import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";

function makeEvent(id: string, at: string | null, action: SessionCwdHistoryEvent["action"] = "change"): SessionCwdHistoryEvent {
  return {
    id,
    sessionId: "sess-replay",
    fromPath: "/",
    toPath: `/${id}`,
    command: `cd /${id}`,
    action,
    status: action === "failed_change" ? "failed" : "confirmed",
    at,
  };
}

const chronologicalEvents = [
  makeEvent("event-a", "2026-09-15T12:00:00.000Z"),
  makeEvent("event-b", "2026-09-15T12:00:05.000Z"),
  makeEvent("event-c", "2026-09-15T12:30:05.000Z"),
];

const replaySession: FilesystemTopologySession = {
  sessionId: "sess-replay",
  sourceIp: "192.0.2.10",
  cwdState: {
    path: "/",
    status: "confirmed",
    observedAt: chronologicalEvents[0].at,
    sourceEventId: null,
  },
  auditSummary: {
    visitedPaths: ["/"],
    homeOnly: false,
    eventCount: chronologicalEvents.length,
  },
};

function fireInputChange(input: HTMLInputElement, value: string): void {
  const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function renderHistory(
  root: Root,
  container: HTMLDivElement,
  overrides: Partial<ComponentProps<typeof CwdRouteHistory>> = {},
) {
  const onSelectHistoryEventId = overrides.onSelectHistoryEventId ?? vi.fn();
  act(() => {
    root.render(
      createElement(CwdRouteHistory, {
        selectedSession: replaySession,
        history: [...chronologicalEvents].reverse(),
        historyStatus: "ready",
        historyCursor: null,
        historyTotalItems: 3,
        historyTotalSuccessfulItems: 3,
        historyComplete: true,
        selectedHistoryEventId: "event-a",
        onSelectHistoryEventId,
        onLoadEarlier: vi.fn(),
        ...overrides,
      }),
    );
  });
  return { onSelectHistoryEventId, range: container.querySelector('input[type="range"]') as HTMLInputElement };
}

describe("FA-009 production replay scrubber", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("uses elapsed milliseconds in the real range input and maps input to the expected event", () => {
    const onSelect = vi.fn();
    const onPause = vi.fn();
    const { range } = renderHistory(root, container, {
      onSelectHistoryEventId: onSelect,
      isPlaying: true,
      onPause,
    });

    expect(range).not.toBeNull();
    expect(range.max).toBe("1805000");
    expect(range.value).toBe("0");
    expect(range.getAttribute("aria-valuemin")).toBe("0");
    expect(range.getAttribute("aria-valuemax")).toBe("1805000");
    expect(range.getAttribute("aria-valuenow")).toBe("0");
    expect(range.getAttribute("aria-valuetext")).toContain("Elapsed time scale");
    expect(range.getAttribute("aria-valuetext")).toContain("Complete retained duration 30m 05s");

    fireInputChange(range, "5000");
    expect(onPause).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith("event-b");
    expect(range.max).not.toBe("2");
  });

  it("does not place the five-second event at the index midpoint", () => {
    const { range } = renderHistory(root, container, {
      selectedHistoryEventId: "event-b",
    });
    expect(range.value).toBe("5000");
    expect(Number(range.value) / Number(range.max)).toBeLessThan(0.01);
  });

  it("keeps previous and next controls hop-based while range input pauses playback", () => {
    const onSelect = vi.fn();
    const onPause = vi.fn();
    renderHistory(root, container, {
      selectedHistoryEventId: "event-b",
      onSelectHistoryEventId: onSelect,
      isPlaying: true,
      onPause,
    });

    const previous = container.querySelector('button[aria-label="Previous hop"]') as HTMLButtonElement;
    const next = container.querySelector('button[aria-label="Next hop"]') as HTMLButtonElement;
    act(() => previous.click());
    act(() => next.click());
    expect(onSelect).toHaveBeenNthCalledWith(1, "event-a");
    expect(onSelect).toHaveBeenNthCalledWith(2, "event-c");
    expect(onPause).toHaveBeenCalledTimes(2);
  });

  it("labels partial loaded span and complete retained duration distinctly", () => {
    renderHistory(root, container, { historyComplete: false });
    expect(container.textContent).toContain("Partial · loaded span 30m 05s");

    renderHistory(root, container, { historyComplete: true });
    expect(container.textContent).toContain("Complete retained duration 30m 05s");
    expect(container.textContent).not.toContain("Partial · loaded span");
  });

  it.each([
    ["missing", [makeEvent("missing-a", null), makeEvent("missing-b", "2026-09-15T12:00:05.000Z")]],
    ["invalid", [makeEvent("invalid-a", "not-a-timestamp"), makeEvent("invalid-b", "2026-09-15T12:00:05.000Z")]],
  ] as const)("visibly reports timing unavailable for %s timestamps", (_name, events) => {
    renderHistory(root, container, {
      history: [...events].reverse(),
      historyTotalItems: 2,
      historyTotalSuccessfulItems: 2,
      selectedHistoryEventId: events[0].id,
    });
    expect(container.textContent).toContain("Timing unavailable");
    const range = container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(range.getAttribute("aria-valuetext")).toContain("Timing unavailable");
  });

  it("disables the scrubber and reports the unloaded gap for an anchored target", () => {
    const anchoredHop = makeEvent("event-deep", "2026-09-15T13:00:00.000Z");
    renderHistory(root, container, {
      anchoredHop,
      selectedHistoryEventId: anchoredHop.id,
      requestedHop: anchoredHop.id,
    });
    const range = container.querySelector('input[type="range"]') as HTMLInputElement;
    expect(range.disabled).toBe(true);
    expect(range.getAttribute("aria-valuetext")).toContain("unloaded gap");
    expect(container.textContent).toContain("unloaded gap");
  });
});

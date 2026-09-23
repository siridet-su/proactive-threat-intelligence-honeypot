// @vitest-environment happy-dom
import { act, createElement, useEffect, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SessionCwdHistoryEvent } from "../src/lib/dashboardTypes";
import {
  deriveAnchoredVerifiedCwdTransition,
  deriveVerifiedCwdTransition,
  deriveVerifiedCwdTransitions,
} from "../src/components/filesystem/filesystemTransitions";
import { useAuditReplay } from "../src/components/filesystem/useAuditReplay";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

function event(
  id: string,
  action: SessionCwdHistoryEvent["action"],
  fromPath: string | null,
  toPath: string | null,
  overrides: Partial<SessionCwdHistoryEvent> = {},
): SessionCwdHistoryEvent {
  return {
    id,
    sessionId: "session-transition-model",
    sequence: null,
    at: "2026-09-23T10:00:00.000Z",
    fromPath,
    toPath,
    action,
    status: action === "failed_change" ? "conditional_candidate" : "confirmed",
    sourceEventId: null,
    ...overrides,
  };
}

function readProbe(container: HTMLElement): {
  displayedHistoryIds: string[];
  displayedTransitions: Array<Record<string, unknown>>;
  currentTransition: Record<string, unknown> | null;
  activeHop: Record<string, unknown> | null;
  showFailedAttempts: boolean;
  isPlaying: boolean;
} {
  return JSON.parse(container.querySelector("pre")?.textContent ?? "null");
}

let latestReplay: ReturnType<typeof useAuditReplay> | null = null;

function ReplayProbe({
  history,
  selectedId,
  anchoredHop = null,
  historyTotalItems = history.length,
  historyComplete = true,
}: {
  history: SessionCwdHistoryEvent[];
  selectedId: string | null;
  anchoredHop?: SessionCwdHistoryEvent | null;
  historyTotalItems?: number;
  historyComplete?: boolean;
}) {
  const replay = useAuditReplay({
    viewMode: "audit",
    history,
    anchoredHop,
    historyTotalItems,
    historyTotalSuccessfulItems: history.filter((item) => item.action !== "failed_change").length,
    historyComplete,
    selectedHistoryEventId: selectedId,
    onSelectHistoryEventId: vi.fn(),
  });
  useEffect(() => {
    latestReplay = replay;
  }, [replay]);

  return createElement(
    "pre",
    null,
    JSON.stringify({
      displayedHistoryIds: replay.displayedHistory.map((item) => item.id),
      displayedTransitions: replay.displayedTransitions,
      currentTransition: replay.currentTransition,
      activeHop: replay.activeHop,
      showFailedAttempts: replay.showFailedAttempts,
      isPlaying: replay.isPlaying,
    }),
  );
}

function ControlledReplayProbe({
  history,
  initialSelectedId,
}: {
  history: SessionCwdHistoryEvent[];
  initialSelectedId: string;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId);
  const replay = useAuditReplay({
    viewMode: "audit",
    history,
    historyTotalItems: history.length,
    historyTotalSuccessfulItems: history.filter((item) => item.action !== "failed_change").length,
    historyComplete: true,
    selectedHistoryEventId: selectedId,
    onSelectHistoryEventId: (id) => setSelectedId(id),
  });
  useEffect(() => {
    latestReplay = replay;
  }, [replay]);

  return createElement(
    "pre",
    null,
    JSON.stringify({
      selectedId,
      displayedHistoryIds: replay.displayedHistory.map((item) => item.id),
      currentTransition: replay.currentTransition,
      activeHop: replay.activeHop,
      isPlaying: replay.isPlaying,
    }),
  );
}

describe("verified CWD transition presentation model", () => {
  it("maps a valid changed event to an exact directed transition", () => {
    const model = deriveVerifiedCwdTransition(
      event("changed-a", "changed", "/home/a", "/tmp"),
      7,
    );

    expect(model).toMatchObject({
      eventId: "changed-a",
      absoluteHop: 7,
      action: "changed",
      presentationKind: "directed",
      fromPath: "/home/a",
      toPath: "/tmp",
      markerPath: null,
    });
  });

  it.each([
    ["missing origin", null, "/tmp"],
    ["missing destination", "/home/a", null],
    ["relative origin", "home/a", "/tmp"],
    ["relative destination", "/home/a", "tmp"],
  ])("makes a changed event with %s unavailable", (_label, fromPath, toPath) => {
    const model = deriveVerifiedCwdTransition(
      event("changed-unavailable", "changed", fromPath, toPath),
      3,
    );

    expect(model).toMatchObject({
      eventId: "changed-unavailable",
      absoluteHop: 3,
      action: "changed",
      presentationKind: "unavailable",
      fromPath: null,
      toPath: null,
      markerPath: null,
    });
  });

  it("maps entered to an entry marker without creating a parent transition", () => {
    const model = deriveVerifiedCwdTransition(
      event("entered-a", "entered", "/attacker/raw-parent", "/home/cowrie"),
      2,
    );

    expect(model).toMatchObject({
      eventId: "entered-a",
      presentationKind: "entry",
      fromPath: null,
      toPath: "/home/cowrie",
      markerPath: "/home/cowrie",
    });
    expect(model.presentationKind).not.toBe("directed");
  });

  it.each([null, "relative/target", ""])("makes entered with invalid target unavailable", (toPath) => {
    const model = deriveVerifiedCwdTransition(
      event("entered-unavailable", "entered", "/raw/from", toPath),
      2,
    );

    expect(model).toMatchObject({
      eventId: "entered-unavailable",
      presentationKind: "unavailable",
      fromPath: null,
      toPath: null,
      markerPath: null,
    });
  });

  it("maps failed changes to their verified origin and never serializes the legacy destination", () => {
    const hostileDestination = "/attacker-controlled/unverified-target";
    const failed = event("failed-a", "failed_change", "/etc/nginx", hostileDestination, {
      status: "unknown",
      at: "2026-09-23T10:02:00.000Z",
    });
    const model = deriveVerifiedCwdTransition(failed, 4);

    expect(model).toMatchObject({
      eventId: failed.id,
      absoluteHop: 4,
      action: "failed_change",
      presentationKind: "failed-origin",
      fromPath: "/etc/nginx",
      toPath: null,
      markerPath: "/etc/nginx",
      observedAt: failed.at,
      status: failed.status,
    });
    expect(JSON.stringify(model)).not.toContain(hostileDestination);
  });

  it("keeps a failed event when its verified origin is unavailable", () => {
    const hostileDestination = "/attacker-controlled/unverified-target";
    const model = deriveVerifiedCwdTransition(
      event("failed-no-origin", "failed_change", null, hostileDestination),
      9,
    );

    expect(model).toMatchObject({
      eventId: "failed-no-origin",
      absoluteHop: 9,
      action: "failed_change",
      presentationKind: "failed-origin",
      fromPath: null,
      toPath: null,
      markerPath: null,
    });
    expect(JSON.stringify(model)).not.toContain(hostileDestination);
  });

  it("preserves timestamp and status, does not mutate the source event, and fails invalid hop values closed", () => {
    const source = event("unchanged", "changed", "/a", "/b", {
      at: "2026-09-23T11:00:00.000Z",
      status: "observed",
      hopNumber: 99,
    });
    const before = JSON.stringify(source);
    const model = deriveVerifiedCwdTransition(source, Number.NaN);

    expect(model.observedAt).toBe(source.at);
    expect(model.status).toBe(source.status);
    expect(model.absoluteHop).toBeNull();
    expect(JSON.stringify(source)).toBe(before);
  });

  it("keeps repeated, reverse, self, and non-parent transitions as separate directed events", () => {
    const transitions = deriveVerifiedCwdTransitions([
      event("a-to-b-1", "changed", "/home/a", "/tmp"),
      event("a-to-b-2", "changed", "/home/a", "/tmp"),
      event("b-to-a", "changed", "/tmp", "/home/a"),
      event("a-to-a", "changed", "/home/a", "/home/a"),
    ], 4);

    expect(transitions).toHaveLength(4);
    expect(transitions.map((transition) => transition.eventId)).toEqual([
      "a-to-b-1",
      "a-to-b-2",
      "b-to-a",
      "a-to-a",
    ]);
    expect(transitions.map((transition) => [transition.fromPath, transition.toPath])).toEqual([
      ["/home/a", "/tmp"],
      ["/home/a", "/tmp"],
      ["/tmp", "/home/a"],
      ["/home/a", "/home/a"],
    ]);
    expect(transitions.every((transition) => transition.presentationKind === "directed")).toBe(true);
  });

  it("assigns loaded absolute hops from the retained all-event window", () => {
    const transitions = deriveVerifiedCwdTransitions([
      event("loaded-a", "changed", "/a", "/b"),
      event("loaded-failed", "failed_change", "/b", "/hostile/legacy"),
    ], 5);

    expect(transitions.map((transition) => transition.absoluteHop)).toEqual([4, 5]);
    expect(JSON.stringify(transitions)).not.toContain("/hostile/legacy");
  });

  it("fails invalid retained totals closed using the loaded window", () => {
    const events = [
      event("safe-a", "changed", "/a", "/b", { hopNumber: 900 }),
      event("safe-b", "changed", "/b", "/c", { hopNumber: 901 }),
    ];

    for (const total of [Number.NaN, Number.POSITIVE_INFINITY, -1, 1.5]) {
      expect(deriveVerifiedCwdTransitions(events, total).map((transition) => transition.absoluteHop)).toEqual([1, 2]);
    }
  });

  it("covers the anchored hop-number boundary matrix and preserves valid hops without a usable retained total", () => {
    const boundaryCases: Array<{
      label: string;
      event: SessionCwdHistoryEvent;
      retainedTotal: number | undefined;
      expectedAbsoluteHop: number | null;
    }> = [
      {
        label: "undefined/absent",
        event: event("anchor-absent", "changed", "/a", "/b"),
        retainedTotal: 10,
        expectedAbsoluteHop: null,
      },
      {
        label: "zero",
        event: event("anchor-zero", "changed", "/a", "/b", { hopNumber: 0 }),
        retainedTotal: 10,
        expectedAbsoluteHop: null,
      },
      {
        label: "negative integer",
        event: event("anchor-negative", "changed", "/a", "/b", { hopNumber: -1 }),
        retainedTotal: 10,
        expectedAbsoluteHop: null,
      },
      {
        label: "fractional number",
        event: event("anchor-fractional", "changed", "/a", "/b", { hopNumber: 2.5 }),
        retainedTotal: 10,
        expectedAbsoluteHop: null,
      },
      {
        label: "NaN",
        event: event("anchor-nan", "changed", "/a", "/b", { hopNumber: Number.NaN }),
        retainedTotal: 10,
        expectedAbsoluteHop: null,
      },
      {
        label: "positive Infinity",
        event: event("anchor-infinity", "changed", "/a", "/b", { hopNumber: Number.POSITIVE_INFINITY }),
        retainedTotal: 10,
        expectedAbsoluteHop: null,
      },
      {
        label: "unsafe integer",
        event: event("anchor-unsafe", "changed", "/a", "/b", { hopNumber: Number.MAX_SAFE_INTEGER + 1 }),
        retainedTotal: Number.MAX_SAFE_INTEGER,
        expectedAbsoluteHop: null,
      },
      {
        label: "valid positive safe integer within retained total",
        event: event("anchor-valid", "changed", "/a", "/b", { hopNumber: 5 }),
        retainedTotal: 10,
        expectedAbsoluteHop: 5,
      },
      {
        label: "valid hop equal to retained total",
        event: event("anchor-at-total", "changed", "/a", "/b", { hopNumber: 10 }),
        retainedTotal: 10,
        expectedAbsoluteHop: 10,
      },
      {
        label: "valid hop greater than retained total",
        event: event("anchor-beyond-total", "changed", "/a", "/b", { hopNumber: 11 }),
        retainedTotal: 10,
        expectedAbsoluteHop: null,
      },
      {
        label: "valid hop with invalid retained total remains usable",
        event: event("anchor-invalid-total", "changed", "/a", "/b", { hopNumber: 5 }),
        retainedTotal: Number.NaN,
        expectedAbsoluteHop: 5,
      },
      {
        label: "valid hop with unavailable retained total remains usable",
        event: event("anchor-unavailable-total", "changed", "/a", "/b", { hopNumber: 5 }),
        retainedTotal: undefined,
        expectedAbsoluteHop: 5,
      },
    ];

    for (const boundaryCase of boundaryCases) {
      expect(
        deriveAnchoredVerifiedCwdTransition(boundaryCase.event, boundaryCase.retainedTotal).absoluteHop,
        boundaryCase.label,
      ).toBe(boundaryCase.expectedAbsoluteHop);
    }

    expect(Object.prototype.hasOwnProperty.call(boundaryCases[0].event, "hopNumber")).toBe(false);
  });

  it("preserves input order and output length", () => {
    const events = [
      event("ordered-entered", "entered", null, "/home/cowrie"),
      event("ordered-failed", "failed_change", "/home/cowrie", "/legacy/unverified"),
      event("ordered-changed", "changed", "/home/cowrie", "/tmp"),
    ];
    const transitions = deriveVerifiedCwdTransitions(events, events.length);

    expect(transitions).toHaveLength(events.length);
    expect(transitions.map((transition) => transition.eventId)).toEqual(events.map((item) => item.id));
  });
});

describe("useAuditReplay transition exposure", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    latestReplay = null;
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    latestReplay = null;
  });

  async function renderProbe(props: {
    history: SessionCwdHistoryEvent[];
    selectedId: string | null;
    anchoredHop?: SessionCwdHistoryEvent | null;
    historyTotalItems?: number;
    historyComplete?: boolean;
  }) {
    await act(async () => {
      root.render(createElement(ReplayProbe, props));
      await Promise.resolve();
    });
  }

  it("aligns loaded displayed transitions with displayed history and current selection", async () => {
    const failed = event("loaded-failed", "failed_change", "/b", "/hostile/legacy");
    const chronological = [
      event("loaded-a", "changed", "/", "/a"),
      failed,
      event("loaded-c", "changed", "/a", "/c"),
    ];

    await renderProbe({
      history: [...chronological].reverse(),
      selectedId: failed.id,
      historyTotalItems: 3,
    });

    const result = readProbe(container);
    expect(result.displayedHistoryIds).toEqual(chronological.map((item) => item.id));
    expect(result.displayedTransitions.map((transition) => transition.eventId)).toEqual(result.displayedHistoryIds);
    expect(result.currentTransition).toMatchObject({
      eventId: failed.id,
      presentationKind: "failed-origin",
      fromPath: "/b",
      toPath: null,
      absoluteHop: 2,
    });
    expect(container.textContent).not.toContain("/hostile/legacy");
  });

  it("filters failed transitions without renumbering the retained absolute hops", async () => {
    const chronological = [
      event("filter-a", "changed", "/", "/a"),
      event("filter-failed", "failed_change", "/a", "/hostile/legacy"),
      event("filter-c", "changed", "/a", "/c"),
    ];

    await renderProbe({
      history: [...chronological].reverse(),
      selectedId: chronological[0].id,
      historyTotalItems: chronological.length,
    });
    expect(latestReplay).not.toBeNull();

    await act(async () => {
      latestReplay?.presentation.onToggleShowFailedAttempts(false);
      await Promise.resolve();
    });

    const result = readProbe(container);
    expect(result.showFailedAttempts).toBe(false);
    expect(result.displayedHistoryIds).toEqual(["filter-a", "filter-c"]);
    expect(result.displayedTransitions.map((transition) => transition.eventId)).toEqual(["filter-a", "filter-c"]);
    expect(result.displayedTransitions.map((transition) => transition.absoluteHop)).toEqual([1, 3]);
  });

  it("derives an anchored successful transition from its authoritative positive hop number", async () => {
    const anchor = event("anchored-success", "changed", "/a", "/b", { hopNumber: 7 });
    const loaded = event("loaded-only", "changed", "/", "/a");

    await renderProbe({
      history: [loaded],
      selectedId: anchor.id,
      anchoredHop: anchor,
      historyTotalItems: 7,
      historyComplete: false,
    });

    const result = readProbe(container);
    expect(result.displayedHistoryIds).toEqual([loaded.id]);
    expect(result.displayedTransitions.map((transition) => transition.eventId)).toEqual([loaded.id]);
    expect(result.currentTransition).toMatchObject({
      eventId: anchor.id,
      presentationKind: "directed",
      fromPath: "/a",
      toPath: "/b",
      absoluteHop: 7,
    });
  });

  it("derives an anchored failed transition without exposing its destination", async () => {
    const hostileDestination = "/attacker-controlled/unverified-target";
    const anchor = event("anchored-failed", "failed_change", "/etc/nginx", hostileDestination, { hopNumber: 8 });
    const loaded = event("loaded-only", "changed", "/", "/a");

    await renderProbe({
      history: [loaded],
      selectedId: anchor.id,
      anchoredHop: anchor,
      historyTotalItems: 8,
      historyComplete: false,
    });

    const result = readProbe(container);
    expect(result.currentTransition).toMatchObject({
      eventId: anchor.id,
      presentationKind: "failed-origin",
      fromPath: "/etc/nginx",
      toPath: null,
      markerPath: "/etc/nginx",
      absoluteHop: 8,
    });
    expect(JSON.stringify(result)).not.toContain(hostileDestination);
  });

  it("fails an anchored transition hop closed when hopNumber is missing or invalid", async () => {
    const zeroAnchor = event("anchored-invalid", "changed", "/a", "/b", { hopNumber: 0 });

    await renderProbe({
      history: [],
      selectedId: zeroAnchor.id,
      anchoredHop: zeroAnchor,
      historyTotalItems: 4,
      historyComplete: false,
    });
    expect(readProbe(container).currentTransition?.absoluteHop).toBeNull();

    const missingHop = event("anchored-missing", "changed", "/a", "/b");
    expect(Object.prototype.hasOwnProperty.call(missingHop, "hopNumber")).toBe(false);
    await renderProbe({
      history: [],
      selectedId: missingHop.id,
      anchoredHop: missingHop,
      historyTotalItems: 4,
      historyComplete: false,
    });
    const result = readProbe(container);
    expect(result.currentTransition).toMatchObject({
      eventId: missingHop.id,
      absoluteHop: null,
    });
    expect(result.displayedHistoryIds).toEqual([]);
    expect(result.displayedTransitions).toEqual([]);
  });

  it("returns no current transition when there is no current event", async () => {
    await renderProbe({ history: [], selectedId: null });
    expect(readProbe(container).currentTransition).toBeNull();
  });

  it("preserves selection, navigation, failed active-hop output, and playback state", async () => {
    const chronological = [
      event("nav-a", "changed", "/", "/a"),
      event("nav-failed", "failed_change", "/a", "/hostile/legacy"),
      event("nav-c", "changed", "/a", "/c"),
    ];
    const history = [...chronological].reverse();

    await act(async () => {
      root.render(createElement(ControlledReplayProbe, {
        history,
        initialSelectedId: "nav-a",
      }));
      await Promise.resolve();
    });

    expect(readProbe(container)).toMatchObject({
      selectedId: "nav-a",
      currentTransition: { eventId: "nav-a", presentationKind: "directed" },
      activeHop: { eventId: "nav-a", toPath: "/a", isFailedAttempt: false },
      isPlaying: false,
    });

    await act(async () => {
      latestReplay?.presentation.onNextHop();
      await Promise.resolve();
    });
    expect(readProbe(container)).toMatchObject({
      selectedId: "nav-failed",
      currentTransition: { eventId: "nav-failed", presentationKind: "failed-origin", toPath: null },
      activeHop: { eventId: "nav-failed", toPath: null, isFailedAttempt: true },
    });

    await act(async () => {
      latestReplay?.presentation.onNextHop();
      await Promise.resolve();
    });
    expect(readProbe(container)).toMatchObject({
      selectedId: "nav-c",
      currentTransition: { eventId: "nav-c", presentationKind: "directed", toPath: "/c" },
      activeHop: { eventId: "nav-c", toPath: "/c", isFailedAttempt: false },
    });

    await act(async () => {
      latestReplay?.presentation.onTogglePlay();
      await Promise.resolve();
    });
    expect(readProbe(container).isPlaying).toBe(true);
    await act(async () => {
      latestReplay?.presentation.onPause();
      await Promise.resolve();
    });
    expect(readProbe(container).isPlaying).toBe(false);
  });
});

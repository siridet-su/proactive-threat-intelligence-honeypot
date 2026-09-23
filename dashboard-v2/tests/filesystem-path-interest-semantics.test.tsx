// @vitest-environment happy-dom
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MotionGlobalConfig } from "framer-motion";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  FilesystemTopologyNode,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
} from "../src/lib/dashboardTypes";
import { FilesystemInspector } from "../src/components/filesystem/FilesystemInspector";
import { TopologyCanvas } from "../src/components/filesystem/TopologyCanvas";
import {
  classifyRuleBasedPathInterest,
  getHistoryWindowMetrics,
  type ActiveHopRoute,
} from "../src/components/filesystem/filesystemUtils";
import { deriveActiveHopRoute } from "../src/components/filesystem/useAuditReplay";

// @ts-expect-error React act environment flag
globalThis.IS_REACT_ACT_ENVIRONMENT = true;

vi.mock("server-only", () => ({}));
MotionGlobalConfig.skipAnimations = true;

const FORBIDDEN_HEURISTIC_CLAIMS = /sensitive target|drop directory|malware|compromised|file drop|file write|payload detected|attacker intent/i;

const RULE_CASES = [
  {
    path: "/root",
    descendant: "/root/.ssh",
    category: "privileged-home",
    categoryLabel: "Privileged account home",
    matchedRoot: "/root",
    ruleDescription: "Privileged account home path rule",
  },
  {
    path: "/tmp",
    descendant: "/tmp/cache",
    category: "temporary-directory",
    categoryLabel: "Temporary directory",
    matchedRoot: "/tmp",
    ruleDescription: "Temporary directory path rule",
  },
  {
    path: "/var/tmp",
    descendant: "/var/tmp/cache",
    category: "temporary-directory",
    categoryLabel: "Temporary directory",
    matchedRoot: "/var/tmp",
    ruleDescription: "Temporary directory path rule",
  },
  {
    path: "/dev/shm",
    descendant: "/dev/shm/session",
    category: "shared-memory",
    categoryLabel: "Shared memory",
    matchedRoot: "/dev/shm",
    ruleDescription: "Shared-memory path rule",
  },
  {
    path: "/etc",
    descendant: "/etc/nginx",
    category: "system-configuration",
    categoryLabel: "System configuration",
    matchedRoot: "/etc",
    ruleDescription: "System configuration path rule",
  },
] as const;

const session: FilesystemTopologySession = {
  sessionId: "session-fsv-006",
  sourceIp: "192.0.2.66",
  cwdState: {
    path: "/tmp",
    status: "confirmed",
    observedAt: "2026-09-23T10:00:00.000Z",
    sourceEventId: null,
  },
  auditSummary: {
    visitedPaths: ["/", "/tmp", "/tmp/cache", "/etc", "/etc/nginx", "/home", "/home/cowrie"],
    homeOnly: false,
    eventCount: 1,
  },
};

function node(path: string, parentPath: string | null, depth: number): FilesystemTopologyNode {
  return {
    path,
    parentPath,
    depth,
    sessionIds: [session.sessionId],
    observedAt: "2026-09-23T10:00:00.000Z",
  };
}

const snapshot: FilesystemTopologySnapshot = {
  nodes: [
    node("/", null, 0),
    node("/tmp", "/", 1),
    node("/tmp/cache", "/tmp", 2),
    node("/etc", "/", 1),
    node("/etc/nginx", "/etc", 2),
    node("/home", "/", 1),
    node("/home/cowrie", "/home", 2),
  ],
  sessions: [session],
  recentClosedSessions: [],
  truncated: false,
  generatedAt: "2026-09-23T10:00:00.000Z",
  latestTelemetryAt: "2026-09-23T10:00:00.000Z",
};

const freshnessState = {
  classification: "fresh" as const,
  label: "Live",
  detail: "Authoritative telemetry is current.",
  badgeClass: "",
  dotClass: "",
  isDegraded: false,
  isStale: false,
  telemetryAgeMs: 0,
  snapshotReceiptAgeMs: 0,
  retrievalAgeMs: 0,
  telemetryStatus: "valid" as const,
};

function assertForbiddenClaimsAbsent(container: HTMLElement): void {
  expect(container.textContent ?? "").not.toMatch(FORBIDDEN_HEURISTIC_CLAIMS);
  expect(container.innerHTML).not.toMatch(FORBIDDEN_HEURISTIC_CLAIMS);

  for (const element of Array.from(container.querySelectorAll("*"))) {
    for (const attribute of Array.from(element.attributes)) {
      expect(attribute.value).not.toMatch(FORBIDDEN_HEURISTIC_CLAIMS);
    }
  }
}

function failedEvent() {
  return {
    id: "failed-fsv-006",
    sessionId: session.sessionId,
    sequence: null,
    sourceEventId: null,
    at: "2026-09-23T10:01:00.000Z",
    fromPath: "/etc",
    toPath: "/tmp/unverified-destination",
    action: "failed_change" as const,
    status: "conditional_candidate" as const,
  };
}

describe("FSV-006 rule-based path interest semantics", () => {
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
    vi.restoreAllMocks();
  });

  it.each(RULE_CASES)("classifies $path and its descendant as a structured path rule", ({ path, descendant, ...expected }) => {
    for (const candidate of [path, descendant]) {
      const interest = classifyRuleBasedPathInterest(candidate);

      expect(interest).toMatchObject({
        source: "path-rule",
        label: "Rule-based path of interest",
        ...expected,
      });
      expect(interest?.explanation).toContain("directory path only");
      expect(interest?.explanation).toContain("not evidence of observed file activity");
      expect(JSON.stringify(interest)).not.toMatch(FORBIDDEN_HEURISTIC_CLAIMS);
    }
  });

  it("rejects segment-boundary collisions and preserves case sensitivity", () => {
    for (const path of ["/tmpfile", "/etcetera", "/rooted", "/dev/shmemory", "/TMP", "/ETC"]) {
      expect(classifyRuleBasedPathInterest(path)).toBeNull();
    }
  });

  it("returns null for an ordinary directory", () => {
    expect(classifyRuleBasedPathInterest("/home/cowrie")).toBeNull();
  });

  it("returns neutral rule wording rather than an evidence claim", () => {
    const interest = classifyRuleBasedPathInterest("/var/tmp/cache");
    const wording = Object.values(interest ?? {}).join(" ");

    expect(wording).toContain("Rule-based path of interest");
    expect(wording).toContain("Temporary directory path rule");
    expect(wording).toContain("/var/tmp");
    expect(wording).toContain("directory path only");
    expect(wording).toContain("not evidence of observed file activity");
    expect(wording).not.toMatch(FORBIDDEN_HEURISTIC_CLAIMS);
  });

  async function renderCanvas(activeHop: ActiveHopRoute | null = null, canvasSnapshot = snapshot) {
    await act(async () => {
      root.render(createElement(TopologyCanvas, {
        snapshot: canvasSnapshot,
        regionStatus: "ready",
        streamState: "live",
        freshnessState,
        selectedSessionId: session.sessionId,
        selectedPath: null,
        activeHop,
        onSelectSession: () => {},
        onSelectPath: () => {},
        staleThresholdMs: 30_000,
        presentationContext: { mode: "live" },
      }));
      await Promise.resolve();
    });
  }

  it("renders an accessible temporary-directory heuristic indicator in Canvas", async () => {
    await renderCanvas();

    const indicator = container.querySelector<HTMLElement>('[data-testid="rule-based-path-interest"]');
    expect(indicator).not.toBeNull();
    expect(container.textContent).toContain("Rule-based path of interest");
    expect(indicator?.innerHTML).toContain("Rule-based path of interest");
    expect(indicator?.getAttribute("aria-label")).toContain("Temporary directory");
    expect(indicator?.getAttribute("aria-label")).toContain("Temporary directory path rule");
    expect(indicator?.getAttribute("aria-label")).toContain("/tmp");
    expect(indicator?.getAttribute("aria-label")).toContain("directory path only");
    expect(indicator?.getAttribute("aria-label")).toContain("not evidence of observed file activity");
    expect(indicator?.getAttribute("title")).toContain("Rule-based path of interest");
    expect(indicator?.querySelector("svg")).not.toBeNull();
    expect(indicator?.getAttribute("role")).toBe("img");
    assertForbiddenClaimsAbsent(container);
  });

  it("does not mark an ordinary Canvas node and keeps a failed destination unmaterialized", async () => {
    const failedRoute = deriveActiveHopRoute(
      [failedEvent()],
      0,
      getHistoryWindowMetrics(1, 1, 0),
    );
    await renderCanvas(failedRoute);

    const normalNode = Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find((button) =>
      button.getAttribute("aria-label")?.includes("/home/cowrie"),
    );
    expect(normalNode).not.toBeUndefined();
    expect(normalNode?.querySelector('[data-testid="rule-based-path-interest"]')).toBeNull();
    expect(container.querySelector('[data-testid="failed-change-annotation"]')).not.toBeNull();
    expect(container.querySelector('[data-testid="active-hop-target-badge"]')).toBeNull();
    expect(container.querySelector('[data-active-hop-connector="true"]')).toBeNull();
    expect(container.textContent).not.toContain("/tmp/unverified-destination");
    expect(container.innerHTML).not.toContain("/tmp/unverified-destination");
    expect(Array.from(container.querySelectorAll("*")).every((element) =>
      Array.from(element.attributes).every((attribute) => !attribute.value.includes("/tmp/unverified-destination")),
    )).toBe(true);
    assertForbiddenClaimsAbsent(container);
  });

  async function renderInspector(selectedNode: FilesystemTopologyNode) {
    await act(async () => {
      root.render(createElement(FilesystemInspector, {
        embedded: true,
        selectedSession: session,
        selectedClosedSession: null,
        selectedNode,
        sessions: [session],
        selectedSessionId: session.sessionId,
        onSelectSession: () => {},
        onSelectPath: () => {},
      }));
      await Promise.resolve();
    });
  }

  it("shows the structured /etc explanation after a user selects the Directory tab", async () => {
    const etcNode = snapshot.nodes.find((candidate) => candidate.path === "/etc");
    expect(etcNode).toBeDefined();
    await renderInspector(etcNode!);

    const directoryTab = container.querySelector<HTMLButtonElement>("#tab-inspector-directory");
    expect(directoryTab).not.toBeNull();
    await act(async () => {
      directoryTab?.click();
      await Promise.resolve();
    });

    const annotation = container.querySelector<HTMLElement>('[data-testid="rule-based-path-interest"]');
    expect(annotation).not.toBeNull();
    expect(annotation?.getAttribute("role")).toBe("note");
    expect(annotation?.getAttribute("aria-label")).toContain("Rule-based path of interest");
    expect(annotation?.getAttribute("aria-label")).toContain("System configuration");
    expect(container.textContent).toContain("Rule-based path of interest");
    expect(container.textContent).toContain("System configuration");
    expect(container.textContent).toContain("Matched rule: System configuration path rule");
    expect(container.textContent).toContain("Matched root: /etc");
    expect(container.textContent).toContain("directory path only");
    expect(container.textContent).toContain("not evidence of observed file activity");
    expect(annotation?.querySelector("svg")).not.toBeNull();
    assertForbiddenClaimsAbsent(container);
  });

  it("does not show a heuristic annotation for an ordinary Inspector path", async () => {
    const normalNode = snapshot.nodes.find((candidate) => candidate.path === "/home/cowrie");
    expect(normalNode).toBeDefined();
    await renderInspector(normalNode!);

    const directoryTab = container.querySelector<HTMLButtonElement>("#tab-inspector-directory");
    await act(async () => {
      directoryTab?.click();
      await Promise.resolve();
    });

    expect(container.querySelector('[data-testid="rule-based-path-interest"]')).toBeNull();
    expect(container.textContent).not.toContain("Rule-based path of interest");
    assertForbiddenClaimsAbsent(container);
  });
});

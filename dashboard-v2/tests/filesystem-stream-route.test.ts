import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FilesystemTopologySnapshot } from "@/lib/dashboardTypes";

const mocks = vi.hoisted(() => ({
  getFilesystemTopology: vi.fn(),
  subscribeFilesystemUpdates: vi.fn(),
  getSessionFromRequest: vi.fn(),
}));

vi.mock("@/lib/filesystem-server", () => ({
  getFilesystemTopology: mocks.getFilesystemTopology,
  subscribeFilesystemUpdates: mocks.subscribeFilesystemUpdates,
}));
vi.mock("@/lib/auth/session", () => ({
  getSessionFromRequest: mocks.getSessionFromRequest,
}));

import { GET } from "@/app/api/filesystem-topology/stream/route";

const initial: FilesystemTopologySnapshot = {
  nodes: [], sessions: [], recentClosedSessions: [], truncated: false,
  generatedAt: "2026-09-23T00:00:00Z", latestTelemetryAt: null,
};

async function readChunk(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<string> {
  const result = await reader.read();
  return result.done ? "" : new TextDecoder().decode(result.value);
}

describe("filesystem SSE delivery contract", () => {
  beforeEach(() => {
    vi.useRealTimers();
    mocks.getSessionFromRequest.mockReset().mockResolvedValue({ mustChangePassword: false });
    mocks.getFilesystemTopology.mockReset().mockResolvedValue(initial);
    mocks.subscribeFilesystemUpdates.mockReset().mockResolvedValue(vi.fn());
  });

  afterEach(() => vi.useRealTimers());

  it("returns headers and a verified snapshot while Change Stream opening is stalled", async () => {
    mocks.subscribeFilesystemUpdates.mockReturnValue(new Promise(() => undefined));
    const response = await GET(new Request("http://localhost/api/filesystem-topology/stream"));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const reader = response.body!.getReader();
    expect(await readChunk(reader)).toContain("retry: 5000");
    expect(await readChunk(reader)).toContain('"sessions":[]');
    await reader.cancel();
  });

  it("polls a changed active session when Change Stream fails", async () => {
    vi.useFakeTimers();
    mocks.subscribeFilesystemUpdates.mockRejectedValue(new Error("watch unavailable"));
    mocks.getFilesystemTopology
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce({ ...initial, sessions: [{ sessionId: "active-1", auditSummary: { visitedPaths: ["/tmp"], homeOnly: false, eventCount: 1 } }] });
    const response = await GET(new Request("http://localhost/api/filesystem-topology/stream"));
    const reader = response.body!.getReader();
    expect(await readChunk(reader)).toContain("retry: 5000");
    expect(await readChunk(reader)).toContain('"sessions":[]');
    const update = readChunk(reader);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await update).toContain("active-1");
    await reader.cancel();
  });

  it("delivers a Change Stream update without waiting for a poll", async () => {
    let changed: ((snapshot: typeof initial) => void) | undefined;
    mocks.subscribeFilesystemUpdates.mockImplementation(({ changed: callback }) => {
      changed = callback;
      return Promise.resolve(vi.fn());
    });
    const response = await GET(new Request("http://localhost/api/filesystem-topology/stream"));
    const reader = response.body!.getReader();
    await readChunk(reader);
    await readChunk(reader);
    changed?.({ ...initial, generatedAt: "2026-09-23T00:00:01Z" });
    expect(await readChunk(reader)).toContain("topology.update");
    await reader.cancel();
  });

  it("does not overwrite a live update with an older in-flight snapshot", async () => {
    vi.useFakeTimers();
    let resolveInitial!: (snapshot: FilesystemTopologySnapshot) => void;
    let changed: ((snapshot: FilesystemTopologySnapshot) => void) | undefined;
    const updated = { ...initial, nodes: [{ path: "/tmp", parentPath: "/", depth: 1, sessionIds: ["active-1"], observedAt: initial.generatedAt }] };
    mocks.getFilesystemTopology
      .mockResolvedValue(updated)
      .mockReturnValueOnce(new Promise((resolve) => { resolveInitial = resolve; }));
    mocks.subscribeFilesystemUpdates.mockImplementation(({ changed: callback }) => {
      changed = callback;
      return Promise.resolve(vi.fn());
    });
    const response = await GET(new Request("http://localhost/api/filesystem-topology/stream"));
    const reader = response.body!.getReader();
    await readChunk(reader);
    expect(mocks.getFilesystemTopology).toHaveBeenCalledTimes(1);
    expect(changed).toBeTypeOf("function");
    changed?.(updated);
    expect(await readChunk(reader)).toContain("/tmp");
    resolveInitial(initial);
    await Promise.resolve();
    const next = readChunk(reader);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(mocks.getFilesystemTopology).toHaveBeenCalledTimes(2);
    // The poll is identical to the change update, so only heartbeat remains.
    await vi.advanceTimersByTimeAsync(15_000);
    expect(await next).toContain("heartbeat");
    await reader.cancel();
  });

  it("rejects unauthenticated requests", async () => {
    mocks.getSessionFromRequest.mockResolvedValue(null);
    expect((await GET(new Request("http://localhost/api/filesystem-topology/stream"))).status).toBe(401);
  });
});

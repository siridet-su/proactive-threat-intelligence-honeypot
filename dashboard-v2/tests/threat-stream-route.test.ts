import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getThreatSnapshot: vi.fn(),
  subscribeThreatUpdates: vi.fn(),
  getSessionFromRequest: vi.fn(),
}));

vi.mock("@/lib/threat-server", () => ({
  getThreatSnapshot: mocks.getThreatSnapshot,
  subscribeThreatUpdates: mocks.subscribeThreatUpdates,
}));
vi.mock("@/lib/auth/session", () => ({
  getSessionFromRequest: mocks.getSessionFromRequest,
}));

import { GET } from "@/app/api/threats/stream/route";

async function readChunk(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<string> {
  const result = await reader.read();
  if (result.done) return "";
  return new TextDecoder().decode(result.value);
}

describe("threat SSE delivery contract", () => {
  let subscriber: ((update: unknown) => void) | null;

  beforeEach(() => {
    vi.useRealTimers();
    subscriber = null;
    mocks.getSessionFromRequest.mockResolvedValue({
      sessionId: "operator-session",
      operatorId: "admin",
      role: "Admin",
      mustChangePassword: false,
    });
    mocks.getThreatSnapshot.mockResolvedValue([]);
    mocks.subscribeThreatUpdates.mockImplementation((callback: (update: unknown) => void) => {
      subscriber = callback;
      return vi.fn();
    });
  });

  it("returns the response and delivers an active-session update without waiting for Mongo", async () => {
    let resolveInitial!: (value: unknown[]) => void;
    mocks.getThreatSnapshot.mockReturnValueOnce(
      new Promise<unknown[]>((resolve) => {
        resolveInitial = resolve;
      }),
    );

    const response = await GET(new Request("http://localhost/api/threats/stream"));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const reader = response.body!.getReader();

    expect(await readChunk(reader)).toContain("retry: 5000");

    resolveInitial([{ id: "active-session" }]);
    expect(await readChunk(reader)).toContain('"active-session"');

    subscriber?.({
      type: "threat.upsert",
      data: { id: "new-active-session" },
    });
    expect(await readChunk(reader)).toContain('"new-active-session"');
    await reader.cancel();
  });

  it("polls and publishes a changed snapshot when the change-stream path emits nothing", async () => {
    vi.useFakeTimers();
    const changedSnapshot = [{ id: "polled-active-session" }];
    mocks.getThreatSnapshot
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce(changedSnapshot);

    const response = await GET(new Request("http://localhost/api/threats/stream"));
    const reader = response.body!.getReader();
    expect(await readChunk(reader)).toContain("retry: 5000");
    expect(await readChunk(reader)).toContain('"data":[]');

    const pendingUpdate = readChunk(reader);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(await pendingUpdate).toContain('"polled-active-session"');
    await reader.cancel();
  });
});

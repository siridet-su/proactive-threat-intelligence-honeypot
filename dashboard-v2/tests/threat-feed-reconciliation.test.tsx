// @vitest-environment happy-dom
import { act, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ThreatFeedProvider, useThreatFeed } from "../src/components/threat/ThreatFeedProvider";

type StreamListener = EventListener;

class MockEventSource {
  listeners: Record<string, StreamListener[]> = {};
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;

  addEventListener(type: string, listener: StreamListener) {
    this.listeners[type] = [...(this.listeners[type] || []), listener];
  }

  close() {
    this.closed = true;
  }

  open() {
    this.onopen?.();
  }

  emit(type: string, data: unknown) {
    const event = { data: JSON.stringify(data) } as MessageEvent<string>;
    this.listeners[type]?.forEach((listener) => listener(event));
  }
}

function threat(id: string) {
  return {
    id,
    timestamp: "2026-10-07T12:00:00Z",
    date: "2026-10-07",
    time: "12:00:00",
    sensor: "test-sensor",
    src_ip: "192.0.2.10",
    sourceIp: "192.0.2.10",
    severity: "Low",
    classification: "SSH",
    typeColor: "blue",
    duration: "0m",
    geo: { lat: 0, lon: 0, country: "Unknown", city: "Unknown" },
    abuseipdb: null,
    virustotal: null,
  };
}

function FeedProbe() {
  const { status, threats } = useThreatFeed();
  return <output data-testid="feed">{status}|{threats.map((item) => item.id).join(",")}</output>;
}

function stubEventSource(onCreate: (source: MockEventSource) => void) {
  const constructor = class EventSourceStub extends MockEventSource {
    constructor() {
      super();
      onCreate(this);
    }
  };
  vi.stubGlobal("EventSource", constructor);
}

describe("threat feed snapshot reconciliation", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("re-fetches REST when SSE remains open but has no data updates", async () => {
    vi.useFakeTimers();
    let source: MockEventSource | null = null;
    stubEventSource((instance) => { source = instance; });
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => [threat("initial-rest")] })
      .mockResolvedValueOnce({ ok: true, json: async () => [threat("reconciled-rest")] });
    vi.stubGlobal("fetch", fetchMock);

    const view = render(<ThreatFeedProvider><FeedProbe /></ThreatFeedProvider>);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(view.getByTestId("feed").textContent).toContain("initial-rest");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    act(() => source?.open());
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(15_000); });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(view.getByTestId("feed").textContent).toContain("reconciled-rest");

    view.unmount();
  });

  it("does not let an older REST response overwrite a newer SSE snapshot", async () => {
    let source: MockEventSource | null = null;
    stubEventSource((instance) => { source = instance; });
    let resolveInitial: ((response: { ok: boolean; json: () => Promise<unknown> }) => void) | null = null;
    vi.stubGlobal("fetch", vi.fn(() => new Promise((resolve) => { resolveInitial = resolve; })));

    const view = render(<ThreatFeedProvider><FeedProbe /></ThreatFeedProvider>);
    act(() => {
      source?.open();
      source?.emit("snapshot", { type: "snapshot", data: [threat("newer-sse")] });
    });
    await act(async () => {
      resolveInitial?.({ ok: true, json: async () => [threat("stale-rest")] });
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(view.getByTestId("feed").textContent).toContain("newer-sse");
    expect(view.getByTestId("feed").textContent).not.toContain("stale-rest");
    view.unmount();
  });
});

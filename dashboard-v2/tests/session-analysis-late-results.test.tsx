// @vitest-environment happy-dom
import { act, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionAnalysisPanels } from "../src/components/threat/SessionAnalysisPanels";

describe("late session analysis results", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("refreshes a closed session until its report and accepted AI advisory are stored", async () => {
    vi.useFakeTimers();
    let detailReads = 0;
    let aiReads = 0;
    const onDetail = vi.fn();
    const initialDetail = {
      ok: true,
      session_id: "session-test",
      session: { status: "closed" },
      reports: [],
    };
    const completedDetail = {
      ...initialDetail,
      reports: [{ report_id: "report-late" }],
      hypothesis_sets: [{
        hypothesis_set_id: "hypothesis-late",
        question: "What explains this observed behavior?",
        hypotheses: [{ hypothesis_id: "hypothesis-late-1", statement: "Late-bound hypothesis is visible." }],
      }],
      response_guidance: { status: "available", guidance_state: "actions_available" },
    };

    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      let data: Record<string, unknown> = { ok: true, session_id: "session-test" };
      if (url.includes("/detail?")) data = ++detailReads === 1 ? initialDetail : completedDetail;
      if (url.includes("/ai-advisory?")) {
        aiReads += 1;
        data = {
          ok: true,
          session_id: "session-test",
          status: aiReads === 1 ? "pending" : "accepted",
          advisory: aiReads === 1 ? {} : { rendered_advisory: { paragraphs: [{ text: "Existing evidence selected." }] } },
        };
      }
      return { ok: true, status: 200, text: async () => JSON.stringify(data) };
    }));

    const view = render(<SessionAnalysisPanels sessionId="session-test" onDetail={onDetail} />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(detailReads).toBe(1);
    expect(aiReads).toBe(1);
    expect(onDetail).toHaveBeenLastCalledWith(initialDetail);

    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(detailReads).toBe(2);
    expect(aiReads).toBe(2);
    expect(onDetail).toHaveBeenLastCalledWith(completedDetail);
    expect(view.container.textContent).toContain("Late-bound hypothesis is visible.");

    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(detailReads).toBe(2);
    expect(aiReads).toBe(2);
    view.unmount();
  });

  it("stops polling at two minutes even when a detail request is still pending", async () => {
    vi.useFakeTimers();
    let detailReads = 0;
    let aiReads = 0;
    const pending: Array<(response: { ok: boolean; status: number; text: () => Promise<string> }) => void> = [];
    const initialDetail = {
      ok: true,
      session_id: "session-test",
      session: { status: "closed" },
      reports: [],
    };
    vi.stubGlobal("fetch", vi.fn((input: string | URL | Request) => {
      const url = String(input);
      if (url.includes("/detail?")) detailReads += 1;
      if (url.includes("/ai-advisory?")) aiReads += 1;
      if ((url.includes("/detail?") && detailReads > 1) || (url.includes("/ai-advisory?") && aiReads > 1)) {
        return new Promise((resolve) => pending.push(resolve));
      }
      const data = url.includes("/detail?")
        ? initialDetail
        : { ok: true, session_id: "session-test", status: "pending", advisory: {} };
      return Promise.resolve({ ok: true, status: 200, text: async () => JSON.stringify(data) });
    }));

    const view = render(<SessionAnalysisPanels sessionId="session-test" />);
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(detailReads).toBe(2);
    expect(aiReads).toBe(2);

    await act(async () => { await vi.advanceTimersByTimeAsync(115_000); });
    expect(detailReads).toBe(2);
    expect(aiReads).toBe(2);
    for (const resolve of pending) {
      resolve({ ok: true, status: 200, text: async () => JSON.stringify(initialDetail) });
    }
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(detailReads).toBe(2);
    view.unmount();
  });
});

// @vitest-environment happy-dom
import { act, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionAnalysisPanels } from "../src/components/threat/SessionAnalysisPanels";

describe("late session analysis results", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("refreshes report projections and AI after a closed session's first snapshot", async () => {
    vi.useFakeTimers();
    let detailReads = 0;
    const onDetail = vi.fn();
    const initialDetail = { ok: true, session_id: "session-test", session: { status: "closed" }, reports: [] };
    const completedDetail = {
      ...initialDetail,
      reports: [{ report_id: "report-late" }],
      hypothesis_sets: [{ hypotheses: [{ hypothesis_id: "hypothesis-late" }] }],
      response_guidance: { status: "available", guidance_state: "actions_available" },
    };
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = String(input);
      let data: Record<string, unknown> = { ok: true, session_id: "session-test" };
      if (url.includes("/detail?")) data = ++detailReads === 1 ? initialDetail : completedDetail;
      if (url.includes("/ai-advisory?")) data = { ...data, status: detailReads === 1 ? "pending" : "accepted" };
      return { ok: true, status: 200, text: async () => JSON.stringify(data) };
    }));

    const view = render(<SessionAnalysisPanels sessionId="session-test" onDetail={onDetail} />);
    await act(async () => { await Promise.resolve(); });
    expect(detailReads).toBe(1);
    expect(onDetail).toHaveBeenCalledWith(initialDetail);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(detailReads).toBe(2);
    expect(onDetail).toHaveBeenLastCalledWith(completedDetail);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(detailReads).toBe(2);
    view.unmount();
  });
});

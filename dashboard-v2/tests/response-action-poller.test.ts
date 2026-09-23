import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SessionTerminateAction } from "../src/lib/dashboardTypes";
import type { TerminateStatePayload } from "../src/components/filesystem/responseActionTypes";
import {
  computePollingDeadline,
  MAX_POLL_DURATION_MS,
  ResponseActionLifecycleManager,
  ResponseActionPollingController,
} from "../src/components/filesystem/responseActionPoller";

describe("ResponseActionPollingController (FA-003)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it("derives absolute deadline from requestedAt and falls back to clock.now() when missing or invalid", () => {
    const baseNow = 1_000_000;
    // Valid requestedAt 5 seconds in the past
    const reqIso = new Date(baseNow - 5_000).toISOString();
    const deadlineFromReq = computePollingDeadline(reqIso, baseNow, 24_000);
    expect(deadlineFromReq).toBe(baseNow - 5_000 + 24_000);

    // Missing requestedAt
    const deadlineMissing = computePollingDeadline(null, baseNow, 24_000);
    expect(deadlineMissing).toBe(baseNow + 24_000);

    // Invalid requestedAt string
    const deadlineInvalid = computePollingDeadline("invalid-date-format", baseNow, 24_000);
    expect(deadlineInvalid).toBe(baseNow + 24_000);
  });

  it("clamps future requestedAt to clock.now() + maxDurationMs against clock skew", () => {
    const baseNow = 1_000_000;
    const futureOffset = 10_000; // 10s in the future due to server/client clock skew
    const reqIso = new Date(baseNow + futureOffset).toISOString();
    const deadlineFromReq = computePollingDeadline(reqIso, baseNow, 24_000);
    // Must be clamped to baseNow + 24_000, NOT baseNow + 10_000 + 24_000
    expect(deadlineFromReq).toBe(baseNow + 24_000);

    // Genuinely old action: requested 30s ago
    const oldReqIso = new Date(baseNow - 30_000).toISOString();
    const oldDeadline = computePollingDeadline(oldReqIso, baseNow, 24_000);
    expect(oldDeadline).toBe(baseNow - 6_000);
  });

  it("times out immediately if action requestedAt is genuinely older than max duration", async () => {
    const onTerminal = vi.fn();
    const oldRequestedAt = new Date(Date.now() - 30_000).toISOString();

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      requestedAt: oldRequestedAt,
      sessionIsLive: false,
      fetchState: vi.fn(async () => ({ available: true })),
      onActionUpdate: vi.fn(),
      onTerminal,
    });

    poller.start();

    expect(onTerminal).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledWith({ kind: "timeout" });
    expect(poller.isTerminal()).toBe(true);
  });

  it("clamps deadline when requestedAt is in the future and stops polling at exactly max duration", async () => {
    const onTerminal = vi.fn();
    const futureRequestedAt = new Date(Date.now() + 10_000).toISOString();

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      requestedAt: futureRequestedAt,
      sessionIsLive: false,
      fetchState: vi.fn(async () => ({
        action: {
          actionId: "act-1",
          sessionId: "sess-1",
          action: "terminate_session",
          status: "delivered",
          requestedBy: "op-1",
          requestedAt: futureRequestedAt,
          deliveredAt: null,
          verifiedAt: null,
          failureCategory: null,
        } as SessionTerminateAction,
        available: true,
      })),
      onActionUpdate: vi.fn(),
      onTerminal,
    });

    poller.start();

    // Advance exactly 24_000ms from start
    await vi.advanceTimersByTimeAsync(MAX_POLL_DURATION_MS);

    // Should have timed out at 24_000ms, not waited 34_000ms
    expect(onTerminal).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledWith({ kind: "timeout" });
    expect(poller.isTerminal()).toBe(true);
  });

  it("keeps one lifecycle and one deadline when status transitions from requested to delivered", async () => {
    const onActionUpdate = vi.fn();
    const onTerminal = vi.fn();

    let callCount = 0;
    const fetchState = vi.fn(async (_sid: string, actionId: string) => {
      callCount++;
      const status = callCount === 1 ? "requested" : "delivered";
      return {
        action: {
          actionId,
          sessionId: "sess-1",
          action: "terminate_session",
          status,
          requestedBy: "op-1",
          requestedAt: new Date(Date.now()).toISOString(),
          deliveredAt: callCount === 1 ? null : new Date(Date.now()).toISOString(),
          verifiedAt: null,
          failureCategory: null,
        } as SessionTerminateAction,
        available: true,
      } as TerminateStatePayload;
    });

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate,
      onTerminal,
    });

    const initialDeadline = poller.deadline;
    poller.start();

    // First attempt at 100ms
    expect(poller.getCurrentDelay()).toBe(100);
    await vi.advanceTimersByTimeAsync(100);

    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(onActionUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ status: "requested" }),
      "available",
    );
    expect(poller.deadline).toBe(initialDeadline);

    // Delay advanced to 150ms monotonically, not reset to 100ms
    expect(poller.getCurrentDelay()).toBe(150);

    // Next attempt fires at 150ms and receives "delivered"
    await vi.advanceTimersByTimeAsync(150);
    expect(fetchState).toHaveBeenCalledTimes(2);
    expect(onActionUpdate).toHaveBeenCalledWith(
      expect.objectContaining({ status: "delivered" }),
      "available",
    );

    poller.abort();
  });

  it("increases delay monotonically and reaches but never exceeds the configured cap (3500ms)", async () => {
    const observedDelays: number[] = [];
    let lastTime = Date.now();

    const fetchState = vi.fn(async () => {
      const now = Date.now();
      observedDelays.push(now - lastTime);
      lastTime = now;
      return {
        action: {
          actionId: "act-1",
          sessionId: "sess-1",
          action: "terminate_session",
          status: "delivered",
          requestedBy: "op-1",
          requestedAt: new Date(Date.now()).toISOString(),
          deliveredAt: null,
          verifiedAt: null,
          failureCategory: null,
        } as SessionTerminateAction,
        available: true,
      } as TerminateStatePayload;
    });

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    poller.start();

    // Expected sequence:
    // attempt 1: delay 100
    // attempt 2: delay 150
    // attempt 3: delay 225
    // attempt 4: delay 338
    // attempt 5: delay 507
    // attempt 6: delay 761
    // attempt 7: delay 1142
    // attempt 8: delay 1713
    // attempt 9: delay 2570
    // attempt 10: delay 3500 (capped!)
    // attempt 11: delay 3500
    const expectedDelays = [100, 150, 225, 338, 507, 761, 1142, 1713, 2570, 3500, 3500];

    for (const delay of expectedDelays) {
      await vi.advanceTimersByTimeAsync(delay);
    }

    expect(observedDelays).toEqual(expectedDelays);
    expect(poller.getCurrentDelay()).toBe(3500);

    poller.abort();
  });

  it("does not repeat non-live initial delay (100ms) after state updates", async () => {
    const fetchState = vi.fn(async () => ({
      action: {
        actionId: "act-1",
        sessionId: "sess-1",
        action: "terminate_session",
        status: "delivered",
        requestedBy: "op-1",
        requestedAt: new Date().toISOString(),
        deliveredAt: null,
        verifiedAt: null,
        failureCategory: null,
      } as SessionTerminateAction,
      available: true,
    } as TerminateStatePayload));

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    poller.start();
    expect(poller.getCurrentDelay()).toBe(100);

    // Fire first poll
    await vi.advanceTimersByTimeAsync(100);
    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(poller.getCurrentDelay()).toBe(150);

    // If 100ms passes, the second poll must NOT have fired yet (it's scheduled at 150ms)
    await vi.advanceTimersByTimeAsync(100);
    expect(fetchState).toHaveBeenCalledTimes(1);

    // Advance remaining 50ms (total 150ms) -> second poll fires
    await vi.advanceTimersByTimeAsync(50);
    expect(fetchState).toHaveBeenCalledTimes(2);
    expect(poller.getCurrentDelay()).toBe(225);

    poller.abort();
  });

  it("prevents request overlap when a request resolves slowly", async () => {
    let resolveSlowFetch: ((value: TerminateStatePayload) => void) | null = null;
    const fetchState = vi.fn(() => new Promise<TerminateStatePayload>((resolve) => {
      resolveSlowFetch = resolve;
    }));

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    poller.start();
    await vi.advanceTimersByTimeAsync(100);
    expect(fetchState).toHaveBeenCalledTimes(1);

    // 1000ms elapses while fetch is still in flight: no second fetch may be initiated
    await vi.advanceTimersByTimeAsync(1000);
    expect(fetchState).toHaveBeenCalledTimes(1);

    // Resolve the slow fetch
    resolveSlowFetch!({
      action: {
        actionId: "act-1",
        sessionId: "sess-1",
        action: "terminate_session",
        status: "delivered",
        requestedBy: "op-1",
        requestedAt: new Date().toISOString(),
        deliveredAt: null,
        verifiedAt: null,
        failureCategory: null,
      } as SessionTerminateAction,
      available: true,
    });
    await Promise.resolve();

    // Now the next attempt is scheduled for 150ms from completion
    await vi.advanceTimersByTimeAsync(149);
    expect(fetchState).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1);
    expect(fetchState).toHaveBeenCalledTimes(2);

    poller.abort();
  });

  it("continues bounded backoff without resetting on network errors", async () => {
    let shouldFail = true;
    const fetchState = vi.fn(async () => {
      if (shouldFail) {
        throw new Error("Network connection lost");
      }
      return {
        action: {
          actionId: "act-1",
          sessionId: "sess-1",
          action: "terminate_session",
          status: "delivered",
          requestedBy: "op-1",
          requestedAt: new Date().toISOString(),
          deliveredAt: null,
          verifiedAt: null,
          failureCategory: null,
        } as SessionTerminateAction,
        available: true,
      } as TerminateStatePayload;
    });

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    poller.start();

    // Attempt 1 at 100ms fails with network error
    await vi.advanceTimersByTimeAsync(100);
    expect(fetchState).toHaveBeenCalledTimes(1);
    // Backoff continues monotonically (150ms) rather than resetting to 100ms
    expect(poller.getCurrentDelay()).toBe(150);

    // Attempt 2 at 150ms fails with network error
    await vi.advanceTimersByTimeAsync(150);
    expect(fetchState).toHaveBeenCalledTimes(2);
    expect(poller.getCurrentDelay()).toBe(225);

    // Attempt 3 succeeds
    shouldFail = false;
    await vi.advanceTimersByTimeAsync(225);
    expect(fetchState).toHaveBeenCalledTimes(3);
    expect(poller.getCurrentDelay()).toBe(338);

    poller.abort();
  });

  it("stops polling and emits verified success feedback exactly once", async () => {
    const onTerminal = vi.fn();
    const verifiedAction: SessionTerminateAction = {
      actionId: "act-1",
      sessionId: "sess-1",
      action: "terminate_session",
      status: "verified",
      requestedBy: "op-1",
      requestedAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString(),
      verifiedAt: new Date().toISOString(),
      failureCategory: null,
    };

    const fetchState = vi.fn(async () => ({
      action: verifiedAction,
      available: false,
    } as TerminateStatePayload));

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal,
    });

    poller.start();
    await vi.advanceTimersByTimeAsync(100);

    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledWith({
      kind: "verified",
      action: verifiedAction,
    });
    expect(poller.isTerminal()).toBe(true);

    // Advance time extensively: no further calls occur
    await vi.advanceTimersByTimeAsync(30_000);
    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledTimes(1);
  });

  it("stops polling and emits failed feedback exactly once", async () => {
    const onTerminal = vi.fn();
    const failedAction: SessionTerminateAction = {
      actionId: "act-1",
      sessionId: "sess-1",
      action: "terminate_session",
      status: "failed",
      requestedBy: "op-1",
      requestedAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString(),
      verifiedAt: null,
      failureCategory: "agent_unreachable",
    };

    const fetchState = vi.fn(async () => ({
      action: failedAction,
      available: false,
    } as TerminateStatePayload));

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal,
    });

    poller.start();
    await vi.advanceTimersByTimeAsync(100);

    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledWith({
      kind: "failed",
      action: failedAction,
      failureCategory: "agent_unreachable",
    });
    expect(poller.isTerminal()).toBe(true);

    await vi.advanceTimersByTimeAsync(30_000);
    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledTimes(1);
  });

  it("stops polling and emits timeout feedback upon reaching deadline", async () => {
    const onTerminal = vi.fn();
    const pendingAction: SessionTerminateAction = {
      actionId: "act-1",
      sessionId: "sess-1",
      action: "terminate_session",
      status: "delivered",
      requestedBy: "op-1",
      requestedAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString(),
      verifiedAt: null,
      failureCategory: null,
    };

    const fetchState = vi.fn(async () => ({
      action: pendingAction,
      available: true,
    } as TerminateStatePayload));

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal,
    });

    poller.start();

    // Advance right up to 24_000ms deadline
    await vi.advanceTimersByTimeAsync(MAX_POLL_DURATION_MS);

    expect(onTerminal).toHaveBeenCalledTimes(1);
    expect(onTerminal).toHaveBeenCalledWith({ kind: "timeout" });
    expect(poller.isTerminal()).toBe(true);

    // Advance further: polling remains stopped
    const callCountAtTimeout = fetchState.mock.calls.length;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetchState).toHaveBeenCalledTimes(callCountAtTimeout);
  });

  it("aborts in-flight request and prevents stale updates on session change", async () => {
    let capturedSignal: AbortSignal | null = null;
    const onActionUpdate = vi.fn();
    const onTerminal = vi.fn();

    const fetchState = vi.fn((_sid: string, _aid: string, signal: AbortSignal) => {
      capturedSignal = signal;
      return new Promise<TerminateStatePayload>((resolve) => {
        // Slow response that resolves after abort
        setTimeout(() => {
          resolve({
            action: {
              actionId: "act-1",
              sessionId: "sess-1",
              action: "terminate_session",
              status: "verified",
              requestedBy: "op-1",
              requestedAt: new Date().toISOString(),
              deliveredAt: null,
              verifiedAt: null,
              failureCategory: null,
            } as SessionTerminateAction,
            available: true,
          });
        }, 500);
      });
    });

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate,
      onTerminal,
    });

    poller.start();
    await vi.advanceTimersByTimeAsync(100);

    expect(fetchState).toHaveBeenCalledTimes(1);
    expect((capturedSignal as AbortSignal | null)?.aborted).toBe(false);

    // Simulate session change: abort old poller
    poller.abort();
    expect((capturedSignal as AbortSignal | null)?.aborted).toBe(true);

    // Advance past slow response completion
    await vi.advanceTimersByTimeAsync(1_000);

    // Stale update must NOT be emitted
    expect(onActionUpdate).not.toHaveBeenCalled();
    expect(onTerminal).not.toHaveBeenCalled();
  });

  it("aborts the previous lifecycle when actionId changes", async () => {
    const onTerminal1 = vi.fn();
    const onTerminal2 = vi.fn();

    const poller1 = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState: vi.fn(async () => ({ available: true })),
      onActionUpdate: vi.fn(),
      onTerminal: onTerminal1,
    });

    poller1.start();
    poller1.abort();
    expect(poller1.isAborted()).toBe(true);

    const poller2 = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-2",
      sessionIsLive: false,
      fetchState: vi.fn(async () => ({ available: true })),
      onActionUpdate: vi.fn(),
      onTerminal: onTerminal2,
    });

    poller2.start();
    expect(poller2.matches("sess-1", "act-2")).toBe(true);
    expect(poller1.matches("sess-1", "act-1")).toBe(false);

    poller2.abort();
  });

  it("cancels timer and in-flight request upon unmount or disable", async () => {
    const fetchState = vi.fn(async () => ({ available: true }));
    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    poller.start();
    // Abort before the first 100ms timer fires
    poller.abort();

    await vi.advanceTimersByTimeAsync(1_000);
    expect(fetchState).not.toHaveBeenCalled();
  });

  it("bounds and asserts total request count over the full deadline", async () => {
    const fetchState = vi.fn(async () => ({
      action: {
        actionId: "act-1",
        sessionId: "sess-1",
        action: "terminate_session",
        status: "delivered",
        requestedBy: "op-1",
        requestedAt: new Date().toISOString(),
        deliveredAt: null,
        verifiedAt: null,
        failureCategory: null,
      } as SessionTerminateAction,
      available: true,
    } as TerminateStatePayload));

    const poller = new ResponseActionPollingController({
      sessionId: "sess-1",
      actionId: "act-1",
      sessionIsLive: false, // 100ms initial delay
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    poller.start();

    // Advance across the entire 24,000ms duration
    await vi.advanceTimersByTimeAsync(MAX_POLL_DURATION_MS);

    // Over 24,000 ms with delays:
    // 100 + 150 + 225 + 338 + 507 + 761 + 1142 + 1713 + 2570 + 3500 + 3500 + 3500 + 3500 = 25,006ms
    // The 13th poll fires at 21,506ms. The 14th poll would be at 25,006ms, but deadline timer fires at 24,000ms.
    // Total requests is strictly 13.
    expect(fetchState).toHaveBeenCalledTimes(13);
  });
});

describe("ResponseActionLifecycleManager Orchestration (FA-003)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
  });

  it("preserves active controller and monotonic delay progression across sessionIsLive true -> false transition", async () => {
    const onActionUpdate = vi.fn();
    const onTerminal = vi.fn();
    const fetchState = vi.fn(async () => ({
      action: {
        actionId: "act-1",
        sessionId: "sess-1",
        action: "terminate_session",
        status: "requested",
        requestedBy: "op-1",
        requestedAt: new Date().toISOString(),
        deliveredAt: null,
        verifiedAt: null,
        failureCategory: null,
      } as SessionTerminateAction,
      available: true,
    }));

    const manager = new ResponseActionLifecycleManager();

    // 1. Initial sync with sessionIsLive = true (live session termination)
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: true,
      enabled: true,
      fetchState,
      onActionUpdate,
      onTerminal,
    });

    const initialController = manager.getController();
    expect(initialController).not.toBeNull();
    // Live session starts with 1,000ms delay
    expect(initialController?.getCurrentDelay()).toBe(1_000);

    // First attempt fires at 1,000ms
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(initialController?.getCurrentDelay()).toBe(1_500);

    // 2. Normal terminate flow: session disappears from live snapshot (sessionIsLive becomes false)
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false, // Changed from true to false!
      enabled: true,
      fetchState,
      onActionUpdate,
      onTerminal,
    });

    // Controller MUST NOT be replaced, aborted, or reset
    expect(manager.getController()).toBe(initialController);
    expect(initialController?.isAborted()).toBe(false);
    // Crucial check: delay must remain 1,500ms, NOT reset to non-live initial 100ms!
    expect(initialController?.getCurrentDelay()).toBe(1_500);

    // 100ms passes: second poll must NOT fire (proves it was not reset to 100ms)
    await vi.advanceTimersByTimeAsync(100);
    expect(fetchState).toHaveBeenCalledTimes(1);

    // Advance remaining 1,400ms (total 1,500ms): second poll fires at 1,500ms
    await vi.advanceTimersByTimeAsync(1_400);
    expect(fetchState).toHaveBeenCalledTimes(2);
    expect(initialController?.getCurrentDelay()).toBe(2_250);

    manager.destroy();
  });

  it("preserves active controller when requestedAt updates or status transitions to delivered", async () => {
    const onActionUpdate = vi.fn();
    const fetchState = vi.fn(async () => ({
      action: {
        actionId: "act-1",
        sessionId: "sess-1",
        action: "terminate_session",
        status: "delivered",
        requestedBy: "op-1",
        requestedAt: new Date().toISOString(),
        deliveredAt: new Date().toISOString(),
        verifiedAt: null,
        failureCategory: null,
      } as SessionTerminateAction,
      available: true,
    }));

    const manager = new ResponseActionLifecycleManager();

    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      requestedAt: new Date().toISOString(),
      enabled: true,
      fetchState,
      onActionUpdate,
      onTerminal: vi.fn(),
    });

    const controller = manager.getController();
    expect(controller).not.toBeNull();
    expect(controller?.getCurrentDelay()).toBe(100);

    await vi.advanceTimersByTimeAsync(100);
    expect(fetchState).toHaveBeenCalledTimes(1);
    expect(controller?.getCurrentDelay()).toBe(150);

    // Reconcile with updated status ("delivered") and new requestedAt string
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "delivered",
      sessionIsLive: false,
      requestedAt: new Date(Date.now() - 500).toISOString(),
      enabled: true,
      fetchState,
      onActionUpdate,
      onTerminal: vi.fn(),
    });

    // Controller must remain the same
    expect(manager.getController()).toBe(controller);
    expect(controller?.getCurrentDelay()).toBe(150);

    // Fires at 150ms monotonically
    await vi.advanceTimersByTimeAsync(150);
    expect(fetchState).toHaveBeenCalledTimes(2);
    expect(controller?.getCurrentDelay()).toBe(225);

    manager.destroy();
  });

  it("bounds request count across live-to-non-live transition and status updates over 24 seconds", async () => {
    const fetchState = vi.fn(async () => ({
      action: {
        actionId: "act-1",
        sessionId: "sess-1",
        action: "terminate_session",
        status: "delivered",
        requestedBy: "op-1",
        requestedAt: new Date().toISOString(),
        deliveredAt: null,
        verifiedAt: null,
        failureCategory: null,
      } as SessionTerminateAction,
      available: true,
    }));

    const manager = new ResponseActionLifecycleManager();

    // Start with live session (1,000ms initial delay)
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: true,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    // Poll 1 at 1,000ms
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fetchState).toHaveBeenCalledTimes(1);

    // Simulate session dropping from live topology and delivered status update
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "delivered",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    // Advance remainder of 24_000ms
    await vi.advanceTimersByTimeAsync(23_000);

    // Over 24,000ms with initial 1,000ms:
    // Delays: 1000 + 1500 + 2250 + 3375 + 3500 + 3500 + 3500 + 3500 = 22,125ms (8 requests).
    // Attempt 9 would be at 25,625ms, which exceeds deadline.
    // If it had reset to 100ms, request count would have surged above 13.
    expect(fetchState).toHaveBeenCalledTimes(8);

    manager.destroy();
  });

  it("aborts previous controller and starts a new lifecycle when sessionId changes", async () => {
    const fetchState = vi.fn(async () => ({ available: true }));
    const manager = new ResponseActionLifecycleManager();

    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    const controller1 = manager.getController();
    expect(controller1).not.toBeNull();
    expect(controller1?.isAborted()).toBe(false);

    // Session changed to sess-2
    manager.sync({
      sessionId: "sess-2",
      actionId: "act-2",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    expect(controller1?.isAborted()).toBe(true);
    const controller2 = manager.getController();
    expect(controller2).not.toBe(controller1);
    expect(controller2?.sessionId).toBe("sess-2");
    expect(controller2?.actionId).toBe("act-2");

    manager.destroy();
  });

  it("aborts previous controller and starts a new lifecycle when actionId changes", async () => {
    const fetchState = vi.fn(async () => ({ available: true }));
    const manager = new ResponseActionLifecycleManager();

    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    const controller1 = manager.getController();

    // Action changed to act-2 on same session
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-2",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    expect(controller1?.isAborted()).toBe(true);
    const controller2 = manager.getController();
    expect(controller2).not.toBe(controller1);
    expect(controller2?.actionId).toBe("act-2");

    manager.destroy();
  });

  it("aborts controller when enabled is toggled to false", async () => {
    const fetchState = vi.fn(async () => ({ available: true }));
    const manager = new ResponseActionLifecycleManager();

    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    const controller = manager.getController();
    expect(controller?.isAborted()).toBe(false);

    // Disabled
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: false,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    expect(controller?.isAborted()).toBe(true);
    expect(manager.getController()).toBeNull();

    manager.destroy();
  });

  it("destroys controller on unmount cleanup", async () => {
    const fetchState = vi.fn(async () => ({ available: true }));
    const manager = new ResponseActionLifecycleManager();

    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal: vi.fn(),
    });

    const controller = manager.getController();
    expect(controller?.isAborted()).toBe(false);

    manager.destroy();

    expect(controller?.isAborted()).toBe(true);
    expect(manager.getController()).toBeNull();
  });

  it("does not restart polling for the same identity after a terminal event occurs", async () => {
    const onTerminal = vi.fn();
    const verifiedAction: SessionTerminateAction = {
      actionId: "act-1",
      sessionId: "sess-1",
      action: "terminate_session",
      status: "verified",
      requestedBy: "op-1",
      requestedAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString(),
      verifiedAt: new Date().toISOString(),
      failureCategory: null,
    };

    const fetchState = vi.fn(async () => ({
      action: verifiedAction,
      available: false,
    }));

    const manager = new ResponseActionLifecycleManager();

    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal,
    });

    // Advance 100ms: poll returns verified
    await vi.advanceTimersByTimeAsync(100);
    expect(onTerminal).toHaveBeenCalledTimes(1);
    expect(fetchState).toHaveBeenCalledTimes(1);

    // Subsequent sync before parent updates actionStatus (e.g. still passed "requested" or "delivered")
    manager.sync({
      sessionId: "sess-1",
      actionId: "act-1",
      actionStatus: "requested",
      sessionIsLive: false,
      enabled: true,
      fetchState,
      onActionUpdate: vi.fn(),
      onTerminal,
    });

    // Must NOT start a new controller
    await vi.advanceTimersByTimeAsync(1_000);
    expect(fetchState).toHaveBeenCalledTimes(1);

    manager.destroy();
  });
});

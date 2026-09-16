import type { SessionTerminateAction } from "@/lib/dashboardTypes";
import type { TerminateCapability, TerminateStatePayload } from "./useResponseAction";
import { terminateCapabilityFrom } from "./useResponseAction";

export const INITIAL_POLL_DELAY_NON_LIVE_MS = 100;
export const INITIAL_POLL_DELAY_LIVE_MS = 1_000;
export const MAX_POLL_DELAY_MS = 3_500;
export const MAX_POLL_DURATION_MS = 24_000;
export const BACKOFF_FACTOR = 1.5;

export type PollerTerminalEvent =
  | { kind: "verified"; action: SessionTerminateAction }
  | { kind: "failed"; action?: SessionTerminateAction; failureCategory?: string | null }
  | { kind: "timeout" };

export interface ResponseActionPollerOptions {
  sessionId: string;
  actionId: string;
  requestedAt?: string | null;
  sessionIsLive?: boolean;
  fetchState: (sessionId: string, actionId: string, signal: AbortSignal) => Promise<TerminateStatePayload>;
  onActionUpdate: (action: SessionTerminateAction | null, capability: TerminateCapability) => void;
  onTerminal: (event: PollerTerminalEvent) => void;
  // Overridable dependencies for deterministic testing
  clock?: { now: () => number };
  timer?: {
    setTimeout: (fn: () => void, ms: number) => unknown;
    clearTimeout: (id: unknown) => void;
  };
  maxDurationMs?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  backoffFactor?: number;
}

export function computePollingDeadline(
  requestedAt: string | null | undefined,
  now: number,
  maxDurationMs: number,
): number {
  if (requestedAt) {
    const reqTime = new Date(requestedAt).getTime();
    if (!Number.isNaN(reqTime)) {
      return reqTime + maxDurationMs;
    }
  }
  return now + maxDurationMs;
}

export class ResponseActionPollingController {
  readonly sessionId: string;
  readonly actionId: string;
  readonly deadline: number;
  readonly maxDelayMs: number;
  readonly backoffFactor: number;

  private currentDelay: number;
  private readonly fetchState: (sessionId: string, actionId: string, signal: AbortSignal) => Promise<TerminateStatePayload>;
  private readonly onActionUpdate: (action: SessionTerminateAction | null, capability: TerminateCapability) => void;
  private readonly onTerminal: (event: PollerTerminalEvent) => void;
  private readonly clock: { now: () => number };
  private readonly timer: {
    setTimeout: (fn: () => void, ms: number) => unknown;
    clearTimeout: (id: unknown) => void;
  };

  private aborted = false;
  private terminal = false;
  private running = false;
  private inFlight = false;
  private pollTimerId: unknown = null;
  private deadlineTimerId: unknown = null;
  private abortController: AbortController | null = null;

  constructor(options: ResponseActionPollerOptions) {
    this.sessionId = options.sessionId;
    this.actionId = options.actionId;
    this.fetchState = options.fetchState;
    this.onActionUpdate = options.onActionUpdate;
    this.onTerminal = options.onTerminal;

    this.clock = options.clock ?? { now: () => Date.now() };
    this.timer = options.timer ?? {
      setTimeout: (fn: () => void, ms: number) => setTimeout(fn, ms),
      clearTimeout: (id: unknown) => clearTimeout(id as ReturnType<typeof setTimeout>),
    };

    const maxDuration = options.maxDurationMs ?? MAX_POLL_DURATION_MS;
    this.deadline = computePollingDeadline(options.requestedAt, this.clock.now(), maxDuration);

    this.maxDelayMs = options.maxDelayMs ?? MAX_POLL_DELAY_MS;
    this.backoffFactor = options.backoffFactor ?? BACKOFF_FACTOR;

    this.currentDelay =
      options.initialDelayMs ??
      (options.sessionIsLive ? INITIAL_POLL_DELAY_LIVE_MS : INITIAL_POLL_DELAY_NON_LIVE_MS);
  }

  matches(sessionId: string, actionId: string): boolean {
    return this.sessionId === sessionId && this.actionId === actionId && !this.aborted && !this.terminal;
  }

  getCurrentDelay(): number {
    return this.currentDelay;
  }

  isAborted(): boolean {
    return this.aborted;
  }

  isTerminal(): boolean {
    return this.terminal;
  }

  start(): void {
    if (this.running || this.aborted || this.terminal) return;
    this.running = true;

    const remaining = this.deadline - this.clock.now();
    if (remaining <= 0) {
      this.handleTimeout();
      return;
    }

    this.deadlineTimerId = this.timer.setTimeout(() => {
      this.handleTimeout();
    }, remaining);

    this.scheduleNextPoll(this.currentDelay);
  }

  private scheduleNextPoll(delayMs: number): void {
    if (this.aborted || this.terminal) return;

    if (this.clock.now() >= this.deadline) {
      this.handleTimeout();
      return;
    }

    this.pollTimerId = this.timer.setTimeout(() => {
      void this.executePoll();
    }, delayMs);
  }

  private async executePoll(): Promise<void> {
    this.pollTimerId = null;
    if (this.aborted || this.terminal) return;

    if (this.clock.now() >= this.deadline) {
      this.handleTimeout();
      return;
    }

    this.inFlight = true;
    this.abortController = new AbortController();

    try {
      const document = await this.fetchState(this.sessionId, this.actionId, this.abortController.signal);
      if (this.aborted || this.terminal) return;
      this.inFlight = false;
      this.abortController = null;

      const action = document.action ?? null;
      const capability = terminateCapabilityFrom(document);
      this.onActionUpdate(action, capability);

      if (action?.status === "verified") {
        this.handleTerminal({ kind: "verified", action });
        return;
      }
      if (action?.status === "failed") {
        this.handleTerminal({
          kind: "failed",
          action,
          failureCategory: action.failureCategory ?? null,
        });
        return;
      }

      // Non-terminal state (requested or delivered): check deadline and schedule next poll
      if (this.clock.now() >= this.deadline) {
        this.handleTimeout();
        return;
      }

      this.currentDelay = Math.min(this.maxDelayMs, Math.round(this.currentDelay * this.backoffFactor));
      this.scheduleNextPoll(this.currentDelay);
    } catch {
      if (this.aborted || this.terminal) return;
      this.inFlight = false;
      this.abortController = null;

      // Network error: continue backoff within the deadline without restarting lifecycle
      if (this.clock.now() >= this.deadline) {
        this.handleTimeout();
        return;
      }

      this.currentDelay = Math.min(this.maxDelayMs, Math.round(this.currentDelay * this.backoffFactor));
      this.scheduleNextPoll(this.currentDelay);
    }
  }

  private handleTerminal(event: PollerTerminalEvent): void {
    if (this.terminal || this.aborted) return;
    this.terminal = true;
    this.cleanup();
    this.onTerminal(event);
  }

  private handleTimeout(): void {
    if (this.terminal || this.aborted) return;
    this.handleTerminal({ kind: "timeout" });
  }

  abort(): void {
    if (this.aborted) return;
    this.aborted = true;
    this.cleanup();
  }

  private cleanup(): void {
    this.running = false;
    if (this.pollTimerId !== null) {
      this.timer.clearTimeout(this.pollTimerId);
      this.pollTimerId = null;
    }
    if (this.deadlineTimerId !== null) {
      this.timer.clearTimeout(this.deadlineTimerId);
      this.deadlineTimerId = null;
    }
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
    this.inFlight = false;
  }
}

import type { ChangeStream } from "mongodb";
import { getMongoClient } from "./mongodb";
import { isHardwareTelemetry } from "./dashboardTypes";
import type { HardwareTelemetry } from "./dashboardTypes";

const DATABASE_NAME = "honeypot_db";
const LIVE_COLLECTION = "hardware_live";
const WATCH_RETRY_MS = 1_000;

type HardwareListener = (metric: HardwareTelemetry) => void;

interface HardwareWatchState {
  listeners: Set<HardwareListener>;
  stream?: ChangeStream;
  runner?: Promise<void>;
}

type HardwareGlobal = typeof globalThis & {
  _ptiHardwareWatchState?: HardwareWatchState;
};

function watchState(): HardwareWatchState {
  const shared = globalThis as HardwareGlobal;
  if (!shared._ptiHardwareWatchState) {
    shared._ptiHardwareWatchState = { listeners: new Set() };
  }
  return shared._ptiHardwareWatchState;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function hardwareTelemetryFromMongoDocument(
  document: unknown,
): HardwareTelemetry | null {
  if (!isHardwareTelemetry(document) || document.timestamp === undefined) {
    return null;
  }
  return document;
}

export async function getRecentHardwareMetrics(
  limit = 30,
): Promise<HardwareTelemetry[]> {
  const client = await getMongoClient();
  const documents = await client
    .db(DATABASE_NAME)
    .collection(LIVE_COLLECTION)
    .find({})
    .sort({ timestamp: -1 })
    .limit(Math.max(1, Math.min(limit, 30)))
    .toArray();

  return documents
    .map(hardwareTelemetryFromMongoDocument)
    .filter((metric): metric is HardwareTelemetry => metric !== null)
    .reverse();
}

function publish(state: HardwareWatchState, document: unknown): void {
  const metric = hardwareTelemetryFromMongoDocument(document);
  if (!metric) return;
  for (const listener of state.listeners) {
    try {
      listener(metric);
    } catch (error) {
      console.error("Hardware SSE listener failed:", error);
    }
  }
}

async function runHardwareWatcher(state: HardwareWatchState): Promise<void> {
  while (state.listeners.size > 0) {
    let stream: ChangeStream | undefined;
    try {
      const client = await getMongoClient();
      stream = client
        .db(DATABASE_NAME)
        .collection(LIVE_COLLECTION)
        .watch([
          { $match: { operationType: { $in: ["insert", "replace"] } } },
        ]);
      state.stream = stream;

      for await (const change of stream) {
        if (
          change.operationType === "insert"
          || change.operationType === "replace"
        ) {
          publish(state, change.fullDocument);
        }
        if (state.listeners.size === 0) break;
      }
    } catch (error) {
      if (state.listeners.size > 0) {
        console.error("Hardware MongoDB change stream failed; retrying:", error);
        await delay(WATCH_RETRY_MS);
      }
    } finally {
      if (state.stream === stream) delete state.stream;
      await stream?.close().catch(() => undefined);
    }
  }
}

function ensureHardwareWatcher(state: HardwareWatchState): void {
  if (state.runner) return;
  state.runner = runHardwareWatcher(state).finally(() => {
    delete state.runner;
    if (state.listeners.size > 0) ensureHardwareWatcher(state);
  });
}

export function subscribeToHardwareMetrics(listener: HardwareListener): () => void {
  const state = watchState();
  state.listeners.add(listener);
  ensureHardwareWatcher(state);
  return () => {
    state.listeners.delete(listener);
    if (state.listeners.size === 0) {
      void state.stream?.close().catch(() => undefined);
    }
  };
}

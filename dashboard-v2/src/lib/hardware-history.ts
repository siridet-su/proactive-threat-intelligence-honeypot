import type { Document } from "mongodb";

import {
  hardwareHistoryMetricNames,
  type HardwareHistoryMetric,
  type HardwareHistoryMetricName,
  type HardwareHistoryMetrics,
  type HardwareHistoryPoint,
  type HardwareHistoryResponse,
} from "./dashboardTypes";
import { getMongoClient } from "./mongodb";

const DATABASE_NAME = "honeypot_db";
const HISTORY_COLLECTION = "hardware_metrics_1m";
const MAX_SOURCE_DOCUMENTS = 50_000;
const MAX_RESPONSE_POINTS = 720;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function finiteNumber(value: unknown): number | null {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value !== "string" || value.trim() === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function asDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  if (typeof value !== "string" && typeof value !== "number") return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function metricStats(value: unknown): HardwareHistoryMetric | null {
  if (isRecord(value)) {
    const min = finiteNumber(value.min);
    const avg = finiteNumber(value.avg);
    const max = finiteNumber(value.max);
    if (min !== null && avg !== null && max !== null) return { min, avg, max };
  }

  const scalar = finiteNumber(value);
  return scalar === null ? null : { min: scalar, avg: scalar, max: scalar };
}

export function normalizeHardwareHistoryDocument(document: unknown): HardwareHistoryPoint | null {
  if (!isRecord(document)) return null;
  const timestamp = asDate(document.timestamp);
  if (!timestamp) return null;

  // Both the compact v2 documents and the older v1 documents keep summaries
  // under `rollup`. Reading top-level scalar fields as a fallback also keeps
  // the endpoint tolerant of earlier rollup records without reintroducing the
  // legacy collection.
  const rollup = isRecord(document.rollup) ? document.rollup : null;
  const source = rollup ?? document;
  const metrics: HardwareHistoryMetrics = {};
  for (const name of hardwareHistoryMetricNames) {
    const value = metricStats(source[name]) ?? (rollup ? metricStats(document[name]) : null);
    if (value) metrics[name] = value;
  }
  if (Object.keys(metrics).length === 0) return null;

  const sampleCount = finiteNumber(document.sample_count);
  return {
    timestamp: timestamp.toISOString(),
    sample_count: sampleCount !== null && sampleCount > 0 ? Math.floor(sampleCount) : 1,
    metrics,
  };
}

type MetricAccumulator = {
  min: number;
  max: number;
  sum: number;
  weight: number;
};

type PointAccumulator = {
  timestamp: number;
  sampleCount: number;
  metrics: Partial<Record<HardwareHistoryMetricName, MetricAccumulator>>;
};

function bucketSizeMilliseconds(from: Date, to: Date): number {
  const requestedMilliseconds = Math.max(60_000, to.getTime() - from.getTime());
  const minutes = Math.max(
    1,
    Math.ceil(requestedMilliseconds / (MAX_RESPONSE_POINTS * 60_000)),
  );
  return minutes * 60_000;
}

export function downsampleHardwareHistory(
  points: HardwareHistoryPoint[],
  from: Date,
  to: Date,
): { bucketSeconds: number; points: HardwareHistoryPoint[] } {
  const bucketMilliseconds = bucketSizeMilliseconds(from, to);
  const buckets = new Map<number, PointAccumulator>();

  for (const point of points) {
    const timestamp = Date.parse(point.timestamp);
    if (!Number.isFinite(timestamp) || timestamp < from.getTime() || timestamp >= to.getTime()) continue;
    const bucketTimestamp = Math.floor(timestamp / bucketMilliseconds) * bucketMilliseconds;
    let bucket = buckets.get(bucketTimestamp);
    if (!bucket) {
      bucket = { timestamp: bucketTimestamp, sampleCount: 0, metrics: {} };
      buckets.set(bucketTimestamp, bucket);
    }

    const weight = Math.max(1, point.sample_count);
    bucket.sampleCount += point.sample_count;
    for (const name of hardwareHistoryMetricNames) {
      const metric = point.metrics[name];
      if (!metric) continue;
      const current = bucket.metrics[name];
      if (!current) {
        bucket.metrics[name] = {
          min: metric.min,
          max: metric.max,
          sum: metric.avg * weight,
          weight,
        };
        continue;
      }
      current.min = Math.min(current.min, metric.min);
      current.max = Math.max(current.max, metric.max);
      current.sum += metric.avg * weight;
      current.weight += weight;
    }
  }

  const result = Array.from(buckets.values())
    .sort((left, right) => left.timestamp - right.timestamp)
    .map((bucket) => {
      const metrics: HardwareHistoryMetrics = {};
      for (const name of hardwareHistoryMetricNames) {
        const current = bucket.metrics[name];
        if (!current) continue;
        metrics[name] = {
          min: current.min,
          avg: current.sum / current.weight,
          max: current.max,
        };
      }
      return {
        timestamp: new Date(bucket.timestamp).toISOString(),
        sample_count: bucket.sampleCount,
        metrics,
      };
    });

  return { bucketSeconds: bucketMilliseconds / 1_000, points: result };
}

export async function getHardwareHistory(
  from: Date,
  to: Date,
  sensorID?: string,
): Promise<HardwareHistoryResponse> {
  const filter: Document = {
    timestamp: { $gte: from, $lt: to },
  };
  if (sensorID) filter.sensor_id = sensorID;

  const client = await getMongoClient();
  const documents = await client
    .db(DATABASE_NAME)
    .collection(HISTORY_COLLECTION)
    .find(filter)
    .project({
      timestamp: 1,
      sensor_id: 1,
      sample_count: 1,
      rollup: 1,
      cpu_percent: 1,
      mem_pressure_percent: 1,
      disk_percent: 1,
      temperature: 1,
      net_wlan0_rx_mbps: 1,
      net_wlan0_tx_mbps: 1,
    })
    .sort({ timestamp: 1 })
    .limit(MAX_SOURCE_DOCUMENTS)
    .toArray();

  const bySensor = new Map<string, HardwareHistoryPoint[]>();
  for (const document of documents) {
    const point = normalizeHardwareHistoryDocument(document);
    if (!point) continue;
    const sensorIDValue = typeof document.sensor_id === "string" && document.sensor_id.trim()
      ? document.sensor_id.trim()
      : "hardware-sensor";
    const points = bySensor.get(sensorIDValue) ?? [];
    points.push(point);
    bySensor.set(sensorIDValue, points);
  }

  const series = Array.from(bySensor.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([id, points]) => {
      const downsampled = downsampleHardwareHistory(points, from, to);
      return { sensor_id: id, points: downsampled.points };
    });

  const bucketSeconds = bucketSizeMilliseconds(from, to) / 1_000;
  return {
    from: from.toISOString(),
    to: to.toISOString(),
    bucket_seconds: bucketSeconds,
    series,
  };
}

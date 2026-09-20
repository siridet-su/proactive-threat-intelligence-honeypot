export type ExternalTiRecord = Record<string, unknown>;

export type ExternalTiFreshness = {
  state: string;
  latestRetrievedAt: string | null;
  freshCacheCount: number;
  staleCacheCount: number;
  staleEvidenceCount: number;
};

function normalized(value: unknown): string {
  return String(value ?? "").trim().toUpperCase();
}

function timestamp(value: unknown): number | null {
  if (typeof value !== "string" && !(value instanceof Date)) return null;
  const parsed = Date.parse(value instanceof Date ? value.toISOString() : value);
  return Number.isFinite(parsed) ? parsed : null;
}

function asOfMilliseconds(asOf: string | number | Date): number {
  if (typeof asOf === "number") return asOf;
  return timestamp(asOf) ?? Date.now();
}

function cacheLookupSucceeded(item: ExternalTiRecord): boolean {
  return ["OK", "CACHED", "AVAILABLE", "NOT_FOUND", "NO_DATA"].includes(
    normalized(item.lookup_status ?? item.status),
  );
}

export function sourceIpCacheFreshness(
  item: ExternalTiRecord,
  asOf: string | number | Date | null = Date.now(),
): string {
  const explicit = normalized(item.freshness_state);
  if (["STALE", "TI_STALE", "EXPIRED", "TI_EXPIRED"].includes(explicit)) return "STALE";
  const expiresAt = timestamp(item.expires_at);
  if (asOf === null) return ["FRESH", "TI_FRESH"].includes(explicit) ? "FRESH" : "NOT_RECORDED";
  if (expiresAt !== null && expiresAt <= asOfMilliseconds(asOf)) return "STALE";
  if (["FRESH", "TI_FRESH"].includes(explicit)) return "FRESH";
  if (!cacheLookupSucceeded(item) || expiresAt === null) return "NOT_RECORDED";
  return "FRESH";
}

function evidenceIsStale(item: ExternalTiRecord, asOf: number): boolean {
  const explicit = normalized(item.freshness_state);
  if (["STALE", "TI_STALE", "EXPIRED", "TI_EXPIRED"].includes(explicit)) return true;
  const expiresAt = timestamp(item.expires_at);
  return expiresAt !== null && expiresAt <= asOf;
}

export function latestExternalTiRetrievalAt(input: {
  freshness?: ExternalTiRecord;
  summary?: ExternalTiRecord;
  evidence?: ExternalTiRecord[];
  cache?: ExternalTiRecord[];
  providerStatus?: ExternalTiRecord;
}): string | null {
  const candidates = [
    input.freshness?.latest_retrieved_at,
    input.summary?.source_ip_cache_latest_lookup_at,
    ...(input.evidence ?? []).map((item) => item.retrieved_at ?? item.lookup_at),
    ...(input.cache ?? []).map((item) => item.lookup_at ?? item.retrieved_at),
    ...Object.values(input.providerStatus ?? {}).map((value) => {
      const item = value && typeof value === "object" ? (value as ExternalTiRecord) : {};
      return item.retrieved_at ?? item.lookup_at;
    }),
  ];
  const latest = candidates
    .map((value) => ({ value, parsed: timestamp(value) }))
    .filter((item): item is { value: string | Date; parsed: number } => item.parsed !== null)
    .sort((left, right) => right.parsed - left.parsed)[0];
  return latest ? new Date(latest.parsed).toISOString() : null;
}

export function externalTiFreshness(input: {
  rawState?: unknown;
  freshness?: ExternalTiRecord;
  summary?: ExternalTiRecord;
  evidence?: ExternalTiRecord[];
  cache?: ExternalTiRecord[];
  providerStatus?: ExternalTiRecord;
  asOf?: string | number | Date | null;
}): ExternalTiFreshness {
  const clockObserved = input.asOf !== null;
  const asOf = input.asOf === null ? 0 : asOfMilliseconds(input.asOf ?? Date.now());
  const cacheStates = (input.cache ?? []).map((item) => sourceIpCacheFreshness(item, clockObserved ? asOf : null));
  const freshCacheCount = cacheStates.filter((state) => state === "FRESH").length;
  const staleCacheCount = cacheStates.filter((state) => state === "STALE").length;
  const staleEvidenceCount = (input.evidence ?? []).filter((item) => evidenceIsStale(item, asOf)).length;
  const rawState = normalized(input.rawState ?? input.freshness?.state);

  let state = rawState || "TI_PENDING";
  if (freshCacheCount > 0 && staleEvidenceCount > 0) state = "MIXED";
  else if (freshCacheCount > 0) state = "FRESH";
  else if (staleEvidenceCount > 0 && !state) state = "STALE";

  return {
    state,
    latestRetrievedAt: latestExternalTiRetrievalAt(input),
    freshCacheCount,
    staleCacheCount,
    staleEvidenceCount,
  };
}

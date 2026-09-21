"use client";

import { useCallback, useEffect, useMemo, useRef, useSyncExternalStore } from "react";

import type {
  AuditDirectorySummary,
  AuditSessionsPage,
  FilesystemClosedSession,
  FilesystemTopologySession,
} from "@/lib/dashboardTypes";
import {
  type DistinctPathOption,
  getDistinctSessionPaths,
  isHomeOnlySession,
  sessionTouchesPath,
} from "./filesystemUtils";
import { getPresetDateRange, type TimeRangeFilter } from "./AuditFilterControls";


export const DEFAULT_AUDIT_DIRECTORY_LIMIT = 50;

export interface AuditScope {
  hideHome: boolean;
  targetPath: string | null;
  q?: string | null;
  from?: number;
  to?: number;
}

export function normalizeAuditScopeTargetPath(path: string | null | undefined): string | null {
  if (!path) return null;
  const trimmed = path.trim();
  if (!trimmed) return null;
  const stripped = trimmed.replace(/\/+$/, "");
  return stripped || "/";
}

export function normalizeAuditScopeQuery(q: string | null | undefined): string | null {
  if (!q) return null;
  const trimmed = q.trim();
  return trimmed ? trimmed.toLowerCase() : null;
}

export function createAuditScopeKey(scope: AuditScope): string {
  const hideHome = Boolean(scope.hideHome);
  const targetPath = normalizeAuditScopeTargetPath(scope.targetPath);
  const q = normalizeAuditScopeQuery(scope.q);
  const from = scope.from;
  const to = scope.to;
  return JSON.stringify([hideHome, targetPath, q, from, to]);
}

export function parseAuditScopeKey(key: string): AuditScope {
  if (!key) {
    return { hideHome: false, targetPath: null, q: null };
  }
  try {
    const parsed = JSON.parse(key);
    if (Array.isArray(parsed) && parsed.length >= 3) {
      return {
        hideHome: Boolean(parsed[0]),
        targetPath: parsed[1] === null ? null : String(parsed[1]),
        q: parsed[2] === null ? null : String(parsed[2]),
        from: typeof parsed[3] === "number" ? parsed[3] : undefined,
        to: typeof parsed[4] === "number" ? parsed[4] : undefined,
      };
    }
    return { hideHome: false, targetPath: null, q: null };
  } catch {
    return { hideHome: false, targetPath: null, q: null };
  }
}

/**
 * Deduplicates and merges closed sessions from the snapshot buffer, audit directory queries,
 * and extra looked-up audit sessions into a single chronologically sorted list.
 */
export function mergeAuthoritativeClosedSessions(
  snapshotRecentClosedSessions: readonly FilesystemClosedSession[] = [],
  auditDirectorySessions:
    | ReadonlyMap<string, FilesystemClosedSession>
    | readonly FilesystemClosedSession[] = [],
  extraAuditSessions?:
    | ReadonlyMap<string, FilesystemClosedSession | FilesystemTopologySession>
    | readonly (FilesystemClosedSession | FilesystemTopologySession)[],
): FilesystemClosedSession[] {
  const sessionMap = new Map<string, FilesystemClosedSession>();

  // 1. Snapshot recent closed sessions (initial 12-item buffer)
  for (const s of snapshotRecentClosedSessions) {
    if (s && s.sessionId) {
      sessionMap.set(s.sessionId, s);
    }
  }

  // 2. Audit directory sessions (fetched remotely from full closed-session collection)
  const auditList =
    auditDirectorySessions instanceof Map
      ? auditDirectorySessions.values()
      : auditDirectorySessions;
  for (const s of auditList) {
    if (s && s.sessionId) {
      sessionMap.set(s.sessionId, s);
    }
  }

  // 3. Extra looked-up audit sessions (e.g. from direct URL deep link or selection)
  if (extraAuditSessions) {
    const extraList =
      extraAuditSessions instanceof Map
        ? extraAuditSessions.values()
        : extraAuditSessions;
    for (const s of extraList) {
      if (
        s &&
        s.sessionId &&
        "lifecycle" in s &&
        Boolean((s as FilesystemClosedSession).lifecycle)
      ) {
        sessionMap.set(s.sessionId, s as FilesystemClosedSession);
      }
    }
  }

  return [...sessionMap.values()].sort((a, b) => {
    const timeA = a.lifecycle?.closedAt ? new Date(a.lifecycle.closedAt).getTime() : 0;
    const timeB = b.lifecycle?.closedAt ? new Date(b.lifecycle.closedAt).getTime() : 0;
    if (timeB !== timeA) return timeB - timeA;
    return a.sessionId.localeCompare(b.sessionId);
  });
}

/**
 * Merges distinct path options from active sessions and server-derived summary facets.
 * Deduplicates by path, summing distinct session occurrences across active and closed sessions.
 */
export function mergeAuthoritativeDistinctPaths(
  activePaths: readonly DistinctPathOption[],
  serverSummaryPaths: readonly DistinctPathOption[] = [],
): DistinctPathOption[] {
  const map = new Map<string, number>();

  for (const p of activePaths) {
    if (p && p.path) {
      map.set(p.path, (map.get(p.path) ?? 0) + p.sessionCount);
    }
  }

  for (const p of serverSummaryPaths) {
    if (p && p.path) {
      map.set(p.path, (map.get(p.path) ?? 0) + p.sessionCount);
    }
  }

  return [...map.entries()]
    .map(([path, sessionCount]) => ({ path, sessionCount }))
    .sort((a, b) => (b.sessionCount !== a.sessionCount ? b.sessionCount - a.sessionCount : a.path.localeCompare(b.path)));
}

export interface BuildAuditSessionsUrlOptions {
  limit?: number;
  cursor?: string | null;
  summary?: boolean;
  q?: string;
  hideHome?: boolean;
  targetPath?: string | null;
  from?: number;
  to?: number;
}

export function buildAuditSessionsUrl({
  limit = DEFAULT_AUDIT_DIRECTORY_LIMIT,
  cursor,
  summary,
  q,
  hideHome,
  targetPath,
  from,
  to,
}: BuildAuditSessionsUrlOptions = {}): string {
  const params = new URLSearchParams();
  if (limit) params.set("limit", String(limit));
  if (cursor) params.set("cursor", cursor);
  if (summary) params.set("summary", "1");
  if (q && q.trim()) params.set("q", q.trim());
  if (hideHome) params.set("hideHome", "1");
  if (targetPath) params.set("targetPath", targetPath);
  if (from != null) params.set("from", String(from));
  if (to != null) params.set("to", String(to));
  const query = params.toString();
  return query ? `/api/filesystem-topology/audit-sessions?${query}` : "/api/filesystem-topology/audit-sessions";
}

export interface PaginationRenderStateOptions {
  effectiveHasMore: boolean;
  effectiveIsLoading: boolean;
  hasItems: boolean;
  isComplete: boolean;
}

/**
 * Pure helper for rendering pagination status.
 * Guarantees strict mutual exclusivity between the action button and completed state text.
 */
export function getPaginationRenderState({
  effectiveHasMore,
  effectiveIsLoading,
  hasItems,
  isComplete,
}: PaginationRenderStateOptions): "button" | "completed" | "none" {
  if (effectiveHasMore) return "button";
  if (!effectiveIsLoading && (hasItems || isComplete)) return "completed";
  return "none";
}

export interface AuthoritativeAuditMetricsOptions {
  viewMode: "live" | "audit";
  activeSessions: readonly FilesystemTopologySession[];
  authoritativeClosedSessions: readonly FilesystemClosedSession[];
  snapshotRecentClosedSessions: readonly FilesystemClosedSession[];
  summary?: AuditDirectorySummary | null;
  summaryScopeKey?: string | null;
  currentScopeKey?: string | null;
  summaryStatus?: "idle" | "loading" | "success" | "error" | "stale";
  auditDirectoryTotalCount?: number | null;
  hideHomeOnly?: boolean;
  targetPathFilter?: string | null;
  selectedSessionId?: string | null;
  isDirectoryComplete?: boolean;
  timeRange?: TimeRangeFilter;
  customDateRange?: DateRange;
}

export function getSessionTimestamp(s: FilesystemTopologySession | FilesystemClosedSession): number {
  if ("lifecycle" in s && s.lifecycle) {
    if (s.lifecycle.startedAt) {
      const t = new Date(s.lifecycle.startedAt).getTime();
      if (!Number.isNaN(t) && t > 0) return t;
    }
    if (s.lifecycle.closedAt) {
      const t = new Date(s.lifecycle.closedAt).getTime();
      if (!Number.isNaN(t) && t > 0) return t;
    }
  }
  if (s.cwdState?.observedAt) {
    const t = new Date(s.cwdState.observedAt).getTime();
    if (!Number.isNaN(t) && t > 0) return t;
  }
  return 0;
}

export interface AuthoritativeAuditMetrics {
  effectiveClosedSessions: FilesystemClosedSession[];
  allSessions: (FilesystemTopologySession | FilesystemClosedSession)[];
  sessionById: Map<string, FilesystemTopologySession | FilesystemClosedSession>;
  distinctPaths: DistinctPathOption[];
  filteredActiveSessions: FilesystemTopologySession[];
  filteredClosedSessions: FilesystemClosedSession[];
  homeOnlyCount: number;
  totalSessionsCount: number;
  filteredSessionsCount: number;
  isSelectedFilteredOut: boolean;
  isAuthoritative: boolean;
}

/**
 * Derives authoritative audit metrics, filter results, totals, and path options.
 * In live mode, strictly preserves snapshot buffer behavior.
 * In audit mode, derives all metrics from the authoritative retained closed sessions and server summary facets.
 * Search results are strictly isolated to selector dropdown options and NEVER replace authoritative closed sessions.
 */
export function deriveAuthoritativeAuditMetrics({
  viewMode,
  activeSessions,
  authoritativeClosedSessions,
  snapshotRecentClosedSessions,
  summary,
  summaryScopeKey,
  currentScopeKey,
  summaryStatus = "success",
  auditDirectoryTotalCount,
  hideHomeOnly = false,
  targetPathFilter = null,
  selectedSessionId = null,
  isDirectoryComplete = false,
  timeRange = "all",
  customDateRange,
}: AuthoritativeAuditMetricsOptions): AuthoritativeAuditMetrics {
  const isAudit = viewMode === "audit";

  // In live mode, effectiveClosedSessions is strictly the snapshot's 12-item buffer.
  // In audit mode, effectiveClosedSessions ALWAYS uses authoritative closed sessions (never replaced by search results!).
  const effectiveClosedSessions = isAudit
    ? [...authoritativeClosedSessions]
    : [...snapshotRecentClosedSessions];

  // Combined sessions with active sessions taking precedence if session ID overlaps
  const allSessions: (FilesystemTopologySession | FilesystemClosedSession)[] = [...activeSessions];
  const seenIds = new Set(activeSessions.map((s) => s.sessionId));
  for (const s of effectiveClosedSessions) {
    if (!seenIds.has(s.sessionId)) {
      seenIds.add(s.sessionId);
      allSessions.push(s);
    }
  }

  const sessionById = new Map<string, FilesystemTopologySession | FilesystemClosedSession>(
    allSessions.map((s) => [s.sessionId, s]),
  );

  const resolvedCurrentScopeKey =
    currentScopeKey ?? createAuditScopeKey({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: (function(){
      if (!timeRange || timeRange === "all") return undefined;
      if (timeRange === "custom") return customDateRange?.from?.getTime();
      return getPresetDateRange(timeRange)?.from?.getTime();
    })(), to: (function(){
      if (!timeRange || timeRange === "all") return undefined;
      if (timeRange === "custom") return customDateRange?.to?.getTime();
      return getPresetDateRange(timeRange)?.to?.getTime();
    })() });
  const resolvedSummaryScopeKey =
    summaryScopeKey !== undefined ? summaryScopeKey : summary ? resolvedCurrentScopeKey : null;

  // Check if summary matches current scope
  const isScopeMatch =
    Boolean(summary) &&
    summaryStatus === "success" &&
    resolvedSummaryScopeKey !== null &&
    resolvedSummaryScopeKey === resolvedCurrentScopeKey;

  // Distinct paths: merge active session paths with server-side closed distinct paths
  // Only use summary.distinctPaths when summaryStatus is success and summaryScopeKey matches currentScopeKey
  let distinctPaths: DistinctPathOption[];
  if (isAudit && isScopeMatch && summary && Array.isArray(summary.distinctPaths) && summary.distinctPaths.length > 0) {
    const activeDistinct = getDistinctSessionPaths(activeSessions, []);
    distinctPaths = mergeAuthoritativeDistinctPaths(activeDistinct, summary.distinctPaths);
  } else {
    distinctPaths = getDistinctSessionPaths(activeSessions, effectiveClosedSessions);
  }

  // Home-only count across all effective sessions
  // Only use summary.homeOnlyCount when summaryStatus is success and summaryScopeKey matches currentScopeKey
  let homeOnlyCount = 0;
  if (isAudit && isScopeMatch && summary && typeof summary.homeOnlyCount === "number") {
    let activeHomeOnly = 0;
    for (const s of activeSessions) {
      if (isHomeOnlySession(s)) activeHomeOnly++;
    }
    homeOnlyCount = activeHomeOnly + summary.homeOnlyCount;
  } else {
    for (const s of allSessions) {
      if (isHomeOnlySession(s)) homeOnlyCount++;
    }
  }

  const hasTimeFilter = Boolean(timeRange && timeRange !== "all");

  // Filter predicate
  const filterFn = (s: FilesystemTopologySession | FilesystemClosedSession) => {
    if (hideHomeOnly && isHomeOnlySession(s)) return false;
    if (targetPathFilter && !sessionTouchesPath(s, targetPathFilter)) return false;
    if (hasTimeFilter && timeRange) {
      let ts = 0;
      if ("lifecycle" in s && s.lifecycle?.closedAt) {
        ts = new Date(s.lifecycle.closedAt).getTime();
        if (Number.isNaN(ts)) ts = 0;
      }
      if (ts > 0) {
        if (timeRange === "custom") {
          if (customDateRange?.from && ts < customDateRange.from.getTime()) return false;
          if (customDateRange?.to && ts > customDateRange.to.getTime()) return false;
        } else {
          const presetRange = getPresetDateRange(timeRange);
          if (presetRange?.from && ts < presetRange.from.getTime()) return false;
          if (presetRange?.to && ts > presetRange.to.getTime()) return false;
        }
      }
    }
    return true;
  };

  const filteredActiveSessions = activeSessions.filter(filterFn);
  const filteredClosedSessions = effectiveClosedSessions.filter(filterFn);

  // Total session count
  // Only use summary.totalSessions or auditDirectoryTotalCount when isScopeMatch is true
  let totalSessionsCount = 0;
  if (isAudit && isScopeMatch && summary && typeof summary.totalSessions === "number") {
    totalSessionsCount = activeSessions.length + summary.totalSessions;
  } else if (isAudit && isScopeMatch && typeof auditDirectoryTotalCount === "number" && auditDirectoryTotalCount > 0) {
    totalSessionsCount = activeSessions.length + auditDirectoryTotalCount;
  } else {
    totalSessionsCount = activeSessions.length + effectiveClosedSessions.length;
  }

  // Filtered sessions count
  let filteredSessionsCount = 0;
  const hasActiveFilters = hideHomeOnly || targetPathFilter !== null || hasTimeFilter;
  const isAuthoritative = !isAudit || (isScopeMatch && Boolean(summary)) || isDirectoryComplete;

  if (hasTimeFilter) {
    filteredSessionsCount = filteredActiveSessions.length + filteredClosedSessions.length;
  } else if (!hasActiveFilters && isAudit) {
    // When no filter is active in audit mode:
    // If scope matches, totalSessionsCount is authoritative.
    // If summary is loading or failed, totalSessionsCount is loaded count, and isAuthoritative is false.
    filteredSessionsCount = totalSessionsCount;
  } else if (
    isAudit &&
    isScopeMatch &&
    hasActiveFilters &&
    targetPathFilter &&
    summary &&
    typeof summary.matchingCount === "number"
  ) {
    // When targetPathFilter is active and server summary provides matchingCount for this scope
    filteredSessionsCount = filteredActiveSessions.length + summary.matchingCount;
  } else if (
    isAudit &&
    isScopeMatch &&
    hasActiveFilters &&
    hideHomeOnly &&
    !targetPathFilter &&
    summary &&
    typeof summary.homeOnlyCount === "number" &&
    typeof summary.totalSessions === "number"
  ) {
    // Home-only filter with valid scope summary
    filteredSessionsCount =
      filteredActiveSessions.length + Math.max(0, summary.totalSessions - summary.homeOnlyCount);
  } else if (isAudit && isScopeMatch && hasActiveFilters && summary && typeof summary.matchingCount === "number") {
    filteredSessionsCount = filteredActiveSessions.length + summary.matchingCount;
  } else {
    // Stale summary, error, or in-flight fetch: explicitly non-authoritative loaded-data fallback
    filteredSessionsCount = filteredActiveSessions.length + filteredClosedSessions.length;
  }

  // Selected session pinned outside filter semantics
  let isSelectedFilteredOut = false;
  if (selectedSessionId && hasActiveFilters) {
    const selectedSession = sessionById.get(selectedSessionId);
    if (selectedSession) {
      if (hideHomeOnly && isHomeOnlySession(selectedSession)) {
        isSelectedFilteredOut = true;
      } else if (targetPathFilter && !sessionTouchesPath(selectedSession, targetPathFilter)) {
        isSelectedFilteredOut = true;
      } else if (hasTimeFilter && !filterFn(selectedSession)) {
        isSelectedFilteredOut = true;
      }
    }
  }

  return {
    effectiveClosedSessions,
    allSessions,
    sessionById,
    distinctPaths,
    filteredActiveSessions,
    filteredClosedSessions,
    homeOnlyCount,
    totalSessionsCount,
    filteredSessionsCount,
    isSelectedFilteredOut,
    isAuthoritative,
  };
}

export interface AuditDirectoryStoreOptions {
  fetchFn?: typeof fetch;
  limit?: number;
}

export interface AuditDirectoryStoreState {
  // Directory state
  directoryItems: FilesystemClosedSession[];
  directoryCursor: string | null;
  directoryHasMore: boolean;
  directoryIsLoading: boolean;
  directoryIsComplete: boolean;
  directoryScopeKey: string;

  // Search state
  searchQuery: string;
  searchItems: FilesystemClosedSession[];
  searchCursor: string | null;
  searchHasMore: boolean;
  searchIsLoading: boolean;
  searchIsComplete: boolean;
  searchScopeKey: string;

  // Summary state
  summary: AuditDirectorySummary | null;
  summaryScopeKey: string | null;
  summaryIsLoading: boolean;
  summaryStatus: "idle" | "loading" | "success" | "error" | "stale";
  summaryError: string | null;

  // Global lifecycle
  status: "idle" | "loading" | "success" | "error";
  errorMessage: string | null;
}

/**
 * Creates an authoritative audit directory store with decoupled directory and search pagination states,
 * generation guards, abort controllers, and scope-bound summary tracking.
 */
export function createAuditDirectoryStore(options: AuditDirectoryStoreOptions = {}) {
  const fetcher =
    options.fetchFn ??
    (typeof fetch !== "undefined"
      ? fetch.bind(globalThis)
      : () => Promise.reject(new Error("fetch is not available")));
  const defaultLimit = options.limit ?? DEFAULT_AUDIT_DIRECTORY_LIMIT;

  let state: AuditDirectoryStoreState = {
    directoryItems: [],
    directoryCursor: null,
    directoryHasMore: false,
    directoryIsLoading: false,
    directoryIsComplete: false,
    directoryScopeKey: "",

    searchQuery: "",
    searchItems: [],
    searchCursor: null,
    searchHasMore: false,
    searchIsLoading: false,
    searchIsComplete: false,
    searchScopeKey: "",

    summary: null,
    summaryScopeKey: null,
    summaryIsLoading: false,
    summaryStatus: "idle",
    summaryError: null,

    status: "idle",
    errorMessage: null,
  };

  const listeners = new Set<() => void>();

  let directoryAbortController: AbortController | null = null;
  let directoryGeneration = 0;

  let searchAbortController: AbortController | null = null;
  let searchGeneration = 0;

  let summaryAbortController: AbortController | null = null;
  let summaryGeneration = 0;

  function notify() {
    for (const l of listeners) {
      l();
    }
  }

  function setState(patch: Partial<AuditDirectoryStoreState>) {
    state = { ...state, ...patch };
    notify();
  }

  const fetchInitial = async (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {
    // When hideHome or targetPath changes (or on any initial scope fetch),
    // abort and clear any active search state before the new directory scope becomes active.
    clearSearch();

    directoryAbortController?.abort();
    directoryAbortController = new AbortController();
    const currentGen = ++directoryGeneration;
    const signal = directoryAbortController.signal;

    const hideHome = Boolean(filterOptions?.hideHome);
    const targetPath = filterOptions?.targetPath ?? null;
    const scopeKey = createAuditScopeKey({ hideHome, targetPath, from: filterOptions?.from, to: filterOptions?.to });

    setState({
      directoryItems: [],
      directoryCursor: null,
      directoryHasMore: false,
      directoryIsComplete: false,
      directoryScopeKey: scopeKey,
      directoryIsLoading: true,
      status: "loading",
      errorMessage: null,
    });

    try {
      const url = buildAuditSessionsUrl({
        limit: defaultLimit,
        hideHome,
        targetPath,
        from: filterOptions?.from,
        to: filterOptions?.to,
      });

      const res = await fetcher(url, { cache: "no-store", signal });
      if (signal.aborted || currentGen !== directoryGeneration) return;
      if (!res.ok) {
        throw new Error(`Server returned status ${res.status}`);
      }
      const data = (await res.json()) as Partial<AuditSessionsPage>;
      if (signal.aborted || currentGen !== directoryGeneration) return;

      if (Array.isArray(data.items)) {
        setState({
          directoryItems: data.items,
          directoryCursor: data.nextCursor ?? null,
          directoryHasMore: Boolean(data.nextCursor),
          directoryIsComplete: !data.nextCursor,
          status: "success",
          directoryIsLoading: false,
        });
      } else {
        throw new Error("Invalid response format");
      }
    } catch (err: unknown) {
      if (signal.aborted || currentGen !== directoryGeneration) return;
      setState({
        status: "error",
        errorMessage: err instanceof Error ? err.message : "Failed to load audit directory",
        directoryIsLoading: false,
      });
    }
  };

  const retryInitial = async (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {
    return fetchInitial(filterOptions);
  };

  const loadMoreDirectory = async () => {
    if (state.directoryIsLoading || !state.directoryHasMore || !state.directoryCursor) return;
    const currentGen = directoryGeneration;
    setState({ directoryIsLoading: true });

    try {
      const parsedScope = parseAuditScopeKey(state.directoryScopeKey);
      const url = buildAuditSessionsUrl({
        limit: defaultLimit,
        cursor: state.directoryCursor,
        hideHome: parsedScope.hideHome,
        targetPath: parsedScope.targetPath,
        from: parsedScope.from,
        to: parsedScope.to,
      });

      const res = await fetcher(url, { cache: "no-store" });
      if (currentGen !== directoryGeneration) return;
      if (!res.ok) return;
      const data = (await res.json()) as Partial<AuditSessionsPage>;
      if (currentGen !== directoryGeneration) return;

      if (Array.isArray(data.items)) {
        const seen = new Set(state.directoryItems.map((s) => s.sessionId));
        const additions = data.items.filter((s) => !seen.has(s.sessionId));
        setState({
          directoryItems: [...state.directoryItems, ...additions],
          directoryCursor: data.nextCursor ?? null,
          directoryHasMore: Boolean(data.nextCursor),
          directoryIsComplete: !data.nextCursor,
          directoryIsLoading: false,
        });
      }
    } catch {
      // ignore pagination network error
    } finally {
      if (currentGen === directoryGeneration) {
        setState({ directoryIsLoading: false });
      }
    }
  };

  const searchSessions = async (
    query: string,
    cursor: string | null = null,
    filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number },
  ) => {
    const trimmed = query.trim();
    if (!trimmed) {
      clearSearch();
      return;
    }

    const hideHome = Boolean(filterOptions?.hideHome);
    const targetPath = filterOptions?.targetPath ?? null;
    const scopeKey = createAuditScopeKey({ hideHome, targetPath, q: trimmed, from: filterOptions?.from, to: filterOptions?.to });

    if (cursor) {
      // Never combine a search cursor created under one scope with filters from another scope.
      if (state.searchScopeKey && state.searchScopeKey !== scopeKey) {
        clearSearch();
        return;
      }
      if (!state.searchCursor || state.searchCursor !== cursor) {
        clearSearch();
        return;
      }
    }

    // Abort previous search request
    searchAbortController?.abort();
    searchAbortController = new AbortController();
    const currentGen = ++searchGeneration;
    const signal = searchAbortController.signal;

    setState({
      searchQuery: trimmed,
      searchScopeKey: scopeKey,
      searchIsLoading: true,
      ...(cursor ? {} : { searchItems: [], searchCursor: null, searchHasMore: false, searchIsComplete: false }),
    });

    try {
      const url = buildAuditSessionsUrl({
        q: trimmed,
        cursor: cursor ?? undefined,
        limit: 25,
        hideHome,
        targetPath,
      });

      const res = await fetcher(url, { cache: "no-store", signal });
      if (signal.aborted || currentGen !== searchGeneration) return;
      if (!res.ok) return;

      const data = (await res.json()) as Partial<AuditSessionsPage>;
      if (signal.aborted || currentGen !== searchGeneration) return;

      if (Array.isArray(data.items)) {
        if (cursor) {
          const seen = new Set(state.searchItems.map((s) => s.sessionId));
          const additions = data.items.filter((s) => !seen.has(s.sessionId));
          setState({
            searchItems: [...state.searchItems, ...additions],
            searchCursor: data.nextCursor ?? null,
            searchHasMore: Boolean(data.nextCursor),
            searchIsComplete: !data.nextCursor,
            searchIsLoading: false,
          });
        } else {
          setState({
            searchItems: data.items,
            searchCursor: data.nextCursor ?? null,
            searchHasMore: Boolean(data.nextCursor),
            searchIsComplete: !data.nextCursor,
            searchIsLoading: false,
          });
        }
      }
    } catch {
      // ignore aborted or network error
    } finally {
      if (currentGen === searchGeneration) {
        setState({ searchIsLoading: false });
      }
    }
  };

  const loadMoreSearch = async (filterOptions?: { hideHome?: boolean; targetPath?: string | null; from?: number; to?: number; }) => {
    if (state.searchIsLoading || !state.searchHasMore || !state.searchCursor || !state.searchQuery) return;
    const parsed = parseAuditScopeKey(state.searchScopeKey);

    // loadMoreSearch must either use the exact stored search scope or reject/reset when the current scope differs.
    if (filterOptions) {
      const requestedHideHome = Boolean(filterOptions.hideHome);
      const requestedTargetPath = filterOptions.targetPath ?? null;
      if (
        requestedHideHome !== parsed.hideHome ||
        normalizeAuditScopeTargetPath(requestedTargetPath) !== normalizeAuditScopeTargetPath(parsed.targetPath)
      ) {
        clearSearch();
        return;
      }
    }

    // Always use the exact stored search scope
    return searchSessions(state.searchQuery, state.searchCursor, {
      hideHome: parsed.hideHome,
      targetPath: parsed.targetPath,
    });
  };

  const clearSearch = () => {
    searchAbortController?.abort();
    searchAbortController = null;
    searchGeneration++;
    setState({
      searchQuery: "",
      searchItems: [],
      searchCursor: null,
      searchHasMore: false,
      searchIsComplete: false,
      searchIsLoading: false,
      searchScopeKey: "",
    });
  };

  const recordLookedUpSession = (session: FilesystemClosedSession) => {
    if (!session || !session.sessionId) return;
    const seen = new Set(state.directoryItems.map((s) => s.sessionId));
    if (seen.has(session.sessionId)) return;
    setState({
      directoryItems: [session, ...state.directoryItems],
    });
  };

  const fetchSummary = async (scope: AuditScope) => {
    summaryAbortController?.abort();
    summaryAbortController = new AbortController();
    const currentGen = ++summaryGeneration;
    const signal = summaryAbortController.signal;

    const scopeKey = createAuditScopeKey(scope);
    setState({
      summaryIsLoading: true,
      summaryStatus: "loading",
      summaryError: null,
    });

    try {
      const params = new URLSearchParams();
      if (scope.hideHome) params.set("hideHome", "1");
      if (scope.targetPath) params.set("targetPath", scope.targetPath);
      if (scope.q?.trim()) params.set("q", scope.q.trim());
      if (scope.from != null) params.set("from", String(scope.from));
      if (scope.to != null) params.set("to", String(scope.to));

      const res = await fetcher(`/api/filesystem-topology/audit-summary?${params.toString()}`, {
        cache: "no-store",
        signal,
      });
      if (signal.aborted || currentGen !== summaryGeneration) return;
      if (!res.ok) {
        throw new Error(`Server returned status ${res.status}`);
      }
      const data = (await res.json()) as unknown;
      if (signal.aborted || currentGen !== summaryGeneration) return;

      const isValidSummary =
        Boolean(data) &&
        typeof data === "object" &&
        data !== null &&
        typeof (data as AuditDirectorySummary).totalSessions === "number" &&
        typeof (data as AuditDirectorySummary).homeOnlyCount === "number" &&
        Array.isArray((data as AuditDirectorySummary).distinctPaths);

      if (isValidSummary) {
        setState({
          summary: data as AuditDirectorySummary,
          summaryScopeKey: scopeKey,
          summaryStatus: "success",
          summaryIsLoading: false,
          summaryError: null,
        });
      } else {
        // An HTTP 2xx response with an invalid summary payload must leave loading state and enter an error state.
        throw new Error("Invalid summary payload received from server");
      }
    } catch (err: unknown) {
      if (signal.aborted || currentGen !== summaryGeneration) return;
      setState({
        summary: null,
        summaryScopeKey: null,
        summaryStatus: "error",
        summaryError: err instanceof Error ? err.message : "Failed to load summary",
        summaryIsLoading: false,
      });
    }
  };

  return {
    getState: () => state,
    subscribe: (listener: () => void) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    fetchInitial,
    retryInitial,
    loadMoreDirectory,
    searchSessions,
    loadMoreSearch,
    clearSearch,
    recordLookedUpSession,
    fetchSummary,
  };
}

import type { DateRange } from "react-day-picker";
export interface UseAuditDirectoryOptions {
  viewMode: "live" | "audit";
  snapshotRecentClosedSessions: readonly FilesystemClosedSession[];
  extraAuditSessions?: Map<string, FilesystemClosedSession | FilesystemTopologySession>;
  hideHomeOnly?: boolean;
  targetPathFilter?: string | null;
  timeRange?: TimeRangeFilter;
  customDateRange?: DateRange;
}

export function useAuditDirectory({
  viewMode,
  snapshotRecentClosedSessions,
  extraAuditSessions,
  hideHomeOnly = false,
  targetPathFilter = null,
  timeRange = "all",
  customDateRange,
}: UseAuditDirectoryOptions) {
  const timeRangeMs = useMemo(() => {
    if (!timeRange || timeRange === "all") return null;
    let from: number | undefined;
    let to: number | undefined;
    if (timeRange === "custom") {
      from = customDateRange?.from?.getTime();
      to = customDateRange?.to?.getTime();
    } else {
      const presetRange = getPresetDateRange(timeRange);
      from = presetRange?.from?.getTime();
      to = presetRange?.to?.getTime();
    }
    return { from, to };
  }, [timeRange, customDateRange]);

  const store = useMemo(() => createAuditDirectoryStore(), []);
  const storeState = useSyncExternalStore(store.subscribe, store.getState, store.getState);

  const prevScopeRef = useRef<string>("");

  // When in audit mode and filter scope changes: abort and clear search, then fetch initial page & summary of the new scope
  useEffect(() => {
    if (viewMode !== "audit") {
      prevScopeRef.current = "";
      return;
    }
    const currentScopeKey = createAuditScopeKey({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });
    if (prevScopeRef.current === currentScopeKey) return;
    prevScopeRef.current = currentScopeKey;

    store.clearSearch();
    void store.fetchInitial({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });
    void store.fetchSummary({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });
  }, [viewMode, hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to, store]);

  const authoritativeClosedSessions = useMemo(() => {
    return mergeAuthoritativeClosedSessions(
      snapshotRecentClosedSessions,
      storeState.directoryItems,
      extraAuditSessions,
    );
  }, [snapshotRecentClosedSessions, storeState.directoryItems, extraAuditSessions]);

  const searchSessions = useCallback(
    async (query: string) => {
      await store.searchSessions(query, null, { hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });
    },
    [store, hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to],
  );

  const loadMoreSearch = useCallback(async () => {
    await store.loadMoreSearch({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });
  }, [store, hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to]);

  const retryInitialDirectory = useCallback(async () => {
    await store.retryInitial({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });
    await store.fetchSummary({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to });
  }, [store, hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to]);

  const currentScopeKey = useMemo(
    () => createAuditScopeKey({ hideHome: hideHomeOnly, targetPath: targetPathFilter, from: timeRangeMs?.from, to: timeRangeMs?.to }),
    [hideHomeOnly, targetPathFilter, timeRangeMs?.from, timeRangeMs?.to],
  );

  return {
    // Directory state
    directoryItems: storeState.directoryItems,
    authoritativeClosedSessions,
    directoryCursor: storeState.directoryCursor,
    directoryHasMore: storeState.directoryHasMore,
    directoryIsLoading: storeState.directoryIsLoading,
    directoryIsComplete: storeState.directoryIsComplete,
    loadMoreDirectory: store.loadMoreDirectory,

    // Search state
    searchQuery: storeState.searchQuery,
    searchItems: storeState.searchItems,
    searchCursor: storeState.searchCursor,
    searchHasMore: storeState.searchHasMore,
    searchIsLoading: storeState.searchIsLoading,
    searchIsComplete: storeState.searchIsComplete,
    searchSessions,
    loadMoreSearch,
    clearSearch: store.clearSearch,

    // Summary / facets state
    summary: storeState.summary,
    summaryScopeKey: storeState.summaryScopeKey,
    currentScopeKey,
    summaryStatus: storeState.summaryStatus,
    summaryIsLoading: storeState.summaryIsLoading,

    // Lifecycle / error state
    status: storeState.status,
    errorMessage: storeState.errorMessage,
    retryInitialDirectory,
    recordLookedUpSession: store.recordLookedUpSession,

    // Backward compatibility aliases
    hasMoreAuditSessions: storeState.directoryHasMore,
    isLoadingAuditSessions: storeState.directoryIsLoading,
    loadMoreAuditSessions: store.loadMoreDirectory,
    auditDirectoryTotalCount:
      (storeState.summaryStatus === "success" && storeState.summaryScopeKey === currentScopeKey
        ? storeState.summary?.totalSessions
        : null) ?? storeState.directoryItems.length,
  };
}

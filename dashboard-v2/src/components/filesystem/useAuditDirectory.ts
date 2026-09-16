"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type {
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

export const DEFAULT_AUDIT_DIRECTORY_LIMIT = 50;

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

export interface AuthoritativeAuditMetricsOptions {
  viewMode: "live" | "audit";
  activeSessions: readonly FilesystemTopologySession[];
  authoritativeClosedSessions: readonly FilesystemClosedSession[];
  snapshotRecentClosedSessions: readonly FilesystemClosedSession[];
  auditDirectoryTotalCount: number | null;
  hideHomeOnly: boolean;
  targetPathFilter: string | null;
  selectedSessionId: string | null;
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
}

/**
 * Derives authoritative audit metrics, filter results, totals, and path options.
 * In live mode, strictly preserves snapshot buffer behavior.
 * In audit mode, derives all metrics from the authoritative retained closed sessions.
 */
export function deriveAuthoritativeAuditMetrics({
  viewMode,
  activeSessions,
  authoritativeClosedSessions,
  snapshotRecentClosedSessions,
  auditDirectoryTotalCount,
  hideHomeOnly,
  targetPathFilter,
  selectedSessionId,
}: AuthoritativeAuditMetricsOptions): AuthoritativeAuditMetrics {
  const isAudit = viewMode === "audit";

  // In live mode, effectiveClosedSessions is strictly the snapshot's 12-item buffer.
  // In audit mode, it is the full authoritative closed session directory.
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

  // Distinct paths with session counts across all effective sessions
  const distinctPaths = getDistinctSessionPaths(activeSessions, effectiveClosedSessions);

  // Home-only count across all effective sessions
  let homeOnlyCount = 0;
  for (const s of allSessions) {
    if (isHomeOnlySession(s)) homeOnlyCount++;
  }

  // Filter predicate
  const filterFn = (s: FilesystemTopologySession | FilesystemClosedSession) => {
    if (hideHomeOnly && isHomeOnlySession(s)) return false;
    if (targetPathFilter && !sessionTouchesPath(s, targetPathFilter)) return false;
    return true;
  };

  const filteredActiveSessions = activeSessions.filter(filterFn);
  const filteredClosedSessions = effectiveClosedSessions.filter(filterFn);
  const filteredSessionsCount = filteredActiveSessions.length + filteredClosedSessions.length;

  // Total session count: in audit mode, truthful to retained directory count
  const effectiveClosedTotal = isAudit
    ? Math.max(effectiveClosedSessions.length, auditDirectoryTotalCount ?? 0)
    : effectiveClosedSessions.length;
  const totalSessionsCount = activeSessions.length + effectiveClosedTotal;

  // Selected session pinned outside filter semantics
  let isSelectedFilteredOut = false;
  const hasActiveFilters = hideHomeOnly || targetPathFilter !== null;
  if (selectedSessionId && hasActiveFilters) {
    const selectedSession = sessionById.get(selectedSessionId);
    if (selectedSession) {
      if (hideHomeOnly && isHomeOnlySession(selectedSession)) {
        isSelectedFilteredOut = true;
      } else if (targetPathFilter && !sessionTouchesPath(selectedSession, targetPathFilter)) {
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
  };
}

export interface UseAuditDirectoryOptions {
  viewMode: "live" | "audit";
  snapshotRecentClosedSessions: readonly FilesystemClosedSession[];
  extraAuditSessions?: Map<string, FilesystemClosedSession | FilesystemTopologySession>;
}

export function useAuditDirectory({
  viewMode,
  snapshotRecentClosedSessions,
  extraAuditSessions,
}: UseAuditDirectoryOptions) {
  const [auditDirectorySessions, setAuditDirectorySessions] = useState<
    Map<string, FilesystemClosedSession>
  >(new Map());
  const [auditDirectoryTotalCount, setAuditDirectoryTotalCount] = useState<number | null>(null);
  const [auditDirectoryCursor, setAuditDirectoryCursor] = useState<string | null>(null);
  const [hasMoreAuditSessions, setHasMoreAuditSessions] = useState(false);
  const [isLoadingAuditSessions, setIsLoadingAuditSessions] = useState(false);

  const initialFetchAttemptedRef = useRef(false);
  const inFlightFetchRef = useRef(false);

  const recordRemoteAuditSessions = useCallback(
    (
      sessions: readonly FilesystemClosedSession[],
      totalCount?: number,
      nextCursor?: string | null,
    ) => {
      if (!sessions || sessions.length === 0) {
        if (typeof totalCount === "number") {
          setAuditDirectoryTotalCount((prev) => Math.max(prev ?? 0, totalCount));
        }
        if (nextCursor !== undefined) {
          setAuditDirectoryCursor(nextCursor);
          setHasMoreAuditSessions(Boolean(nextCursor));
        }
        return;
      }

      setAuditDirectorySessions((prev) => {
        const next = new Map(prev);
        let changed = false;
        for (const s of sessions) {
          if (s && s.sessionId) {
            next.set(s.sessionId, s);
            changed = true;
          }
        }
        return changed ? next : prev;
      });

      if (typeof totalCount === "number") {
        setAuditDirectoryTotalCount((prev) => Math.max(prev ?? 0, totalCount));
      }
      if (nextCursor !== undefined) {
        setAuditDirectoryCursor(nextCursor);
        setHasMoreAuditSessions(Boolean(nextCursor));
      }
    },
    [],
  );

  const fetchAuditDirectoryPage = useCallback(
    async (cursor: string | null, limit = DEFAULT_AUDIT_DIRECTORY_LIMIT) => {
      if (inFlightFetchRef.current) return;
      inFlightFetchRef.current = true;
      setIsLoadingAuditSessions(true);

      try {
        const params = new URLSearchParams();
        if (cursor) params.set("cursor", cursor);
        params.set("limit", String(limit));

        const response = await fetch(
          `/api/filesystem-topology/audit-sessions?${params.toString()}`,
          { cache: "no-store" },
        );
        if (!response.ok) return;

        const data: unknown = await response.json();
        const page = data as Partial<AuditSessionsPage>;
        if (Array.isArray(page.items)) {
          recordRemoteAuditSessions(page.items, page.totalItems, page.nextCursor ?? null);
        }
      } catch {
        // preserve existing directory sessions on network failure
      } finally {
        inFlightFetchRef.current = false;
        setIsLoadingAuditSessions(false);
      }
    },
    [recordRemoteAuditSessions],
  );

  // Trigger initial fetch when entering audit mode if not yet fetched
  useEffect(() => {
    if (viewMode !== "audit") return;
    if (initialFetchAttemptedRef.current) return;
    initialFetchAttemptedRef.current = true;
    void fetchAuditDirectoryPage(null);
  }, [viewMode, fetchAuditDirectoryPage]);

  const loadMoreAuditSessions = useCallback(async () => {
    if (isLoadingAuditSessions || !hasMoreAuditSessions || !auditDirectoryCursor) return;
    await fetchAuditDirectoryPage(auditDirectoryCursor);
  }, [isLoadingAuditSessions, hasMoreAuditSessions, auditDirectoryCursor, fetchAuditDirectoryPage]);

  const authoritativeClosedSessions = useMemo(() => {
    return mergeAuthoritativeClosedSessions(
      snapshotRecentClosedSessions,
      auditDirectorySessions,
      extraAuditSessions,
    );
  }, [snapshotRecentClosedSessions, auditDirectorySessions, extraAuditSessions]);

  return {
    auditDirectorySessions,
    authoritativeClosedSessions,
    auditDirectoryTotalCount,
    hasMoreAuditSessions,
    isLoadingAuditSessions,
    loadMoreAuditSessions,
    recordRemoteAuditSessions,
  };
}

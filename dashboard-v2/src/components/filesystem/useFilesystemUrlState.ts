"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
} from "@/lib/dashboardTypes";
import {
  parseAuditUrlParams,
  resolveSessionSelection,
} from "./filesystemUtils";
import type {
  RemoteAuditLookupCoordinator,
  RemoteAuditLookupIntent,
} from "./sessionHopResolver";
import {
  FilesystemNavigationCoordinator,
  type NavigationStateCommitOptions,
  type PopStateTransaction,
} from "./filesystemNavigationCoordinator";

export {
  FilesystemNavigationCoordinator,
  type NavigationStateCommitOptions,
  type PopStateTransaction,
};

export interface UseFilesystemUrlStateOptions {
  isHydrated: boolean;
  snapshot: FilesystemTopologySnapshot | null;
  extraAuditSessions: Map<string, FilesystemClosedSession | FilesystemTopologySession>;
  setExtraAuditSessions?: (
    updater: (
      prev: Map<string, FilesystemClosedSession | FilesystemTopologySession>,
    ) => Map<string, FilesystemClosedSession | FilesystemTopologySession>,
  ) => void;
  selectedSessionId: string | null;
  selectedSessionIdRef?: React.MutableRefObject<string | null>;
  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  selectSession?: (
    sessionId: string,
    sessionObj?: FilesystemTopologySession | FilesystemClosedSession,
    targetHopId?: string | null,
  ) => void;
  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  lookupRemoteAuditSession?: (intent: RemoteAuditLookupIntent) => Promise<void> | void;
  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  coordinator?: RemoteAuditLookupCoordinator;
  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  onExitFullscreenAndPlaying?: () => void;
  setSelectedSessionId?: (id: string | null) => void;

  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  allSessions?: FilesystemTopologySession[];
  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  sessionById?: Map<string, FilesystemTopologySession | FilesystemClosedSession>;
  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  resetHistory?: () => void;
  /** @deprecated Bind domain callbacks via navigationCoordinator.bindDomainAdapter() instead */
  resetRequestedHopState?: () => void;
}

export interface UseFilesystemUrlStateReturn {
  viewMode: "live" | "audit";
  setViewMode: React.Dispatch<React.SetStateAction<"live" | "audit">>;
  viewModeRef: React.MutableRefObject<"live" | "audit">;
  switchViewMode: (mode: "live" | "audit", targetSessionId?: string) => void;
  hideHomeOnly: boolean;
  setHideHomeOnly: React.Dispatch<React.SetStateAction<boolean>>;
  targetPathFilter: string | null;
  setTargetPathFilter: React.Dispatch<React.SetStateAction<string | null>>;
  selectedHistoryEventId: string | null;
  setSelectedHistoryEventId: React.Dispatch<React.SetStateAction<string | null>>;
  expiredSessionId: string | null;
  setExpiredSessionId: React.Dispatch<React.SetStateAction<string | null>>;
  requestedHopRef: React.MutableRefObject<string | null>;
  requestedSessionIdRef: React.MutableRefObject<string | null>;
  commitUserNavigation: (updates: NavigationStateCommitOptions) => void;
  commitPlaybackNavigation: (hopId: string | null) => void;
  navigationCoordinator: FilesystemNavigationCoordinator;
}

export function useFilesystemUrlState(
  options: UseFilesystemUrlStateOptions,
): UseFilesystemUrlStateReturn {
  const {
    isHydrated,
    snapshot,
    extraAuditSessions,
    selectedSessionId,
    setSelectedSessionId,
  } = options;

  const [viewMode, setViewMode] = useState<"live" | "audit">(() => {
    if (typeof window === "undefined") return "live";
    const parsed = parseAuditUrlParams(window.location.search);
    return parsed.view ?? "live";
  });
  const [hideHomeOnly, setHideHomeOnly] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    const parsed = parseAuditUrlParams(window.location.search);
    return Boolean(parsed.hideHome);
  });
  const [targetPathFilter, setTargetPathFilter] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    const parsed = parseAuditUrlParams(window.location.search);
    return parsed.targetPath ?? null;
  });
  const [selectedHistoryEventId, setSelectedHistoryEventId] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    const parsed = parseAuditUrlParams(window.location.search);
    return parsed.hop ?? null;
  });
  const [expiredSessionId, setExpiredSessionId] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    const parsed = parseAuditUrlParams(window.location.search);
    return parsed.sessionId ?? null;
  });

  const requestedHopRef = useRef<string | null>(selectedHistoryEventId);
  const requestedSessionIdRef = useRef<string | null>(
    typeof window !== "undefined" ? parseAuditUrlParams(window.location.search).sessionId ?? null : null,
  );

  const fallbackSelectedSessionIdRef = useRef<string | null>(selectedSessionId);
  const activeSessionIdRef = options.selectedSessionIdRef ?? fallbackSelectedSessionIdRef;

  const viewModeRef = useRef<"live" | "audit">(viewMode);
  const hideHomeOnlyRef = useRef<boolean>(hideHomeOnly);
  const targetPathFilterRef = useRef<string | null>(targetPathFilter);
  const selectedHistoryEventIdRef = useRef<string | null>(selectedHistoryEventId);
  const expiredSessionIdRef = useRef<string | null>(expiredSessionId);

  useEffect(() => {
    viewModeRef.current = viewMode;
  }, [viewMode]);

  useEffect(() => {
    hideHomeOnlyRef.current = hideHomeOnly;
  }, [hideHomeOnly]);

  useEffect(() => {
    targetPathFilterRef.current = targetPathFilter;
  }, [targetPathFilter]);

  useEffect(() => {
    selectedHistoryEventIdRef.current = selectedHistoryEventId;
  }, [selectedHistoryEventId]);

  useEffect(() => {
    if (!options.selectedSessionIdRef) {
      fallbackSelectedSessionIdRef.current = selectedSessionId;
    }
  }, [options.selectedSessionIdRef, selectedSessionId]);

  useEffect(() => {
    expiredSessionIdRef.current = expiredSessionId;
  }, [expiredSessionId]);

  const [navigationCoordinator] = useState(() => new FilesystemNavigationCoordinator());

  // Synchronize dynamic URL state bindings owned exclusively by useFilesystemUrlState
  useEffect(() => {
    navigationCoordinator.bindUrlState({
      getViewMode: () => viewModeRef.current,
      getSelectedSessionId: () => activeSessionIdRef.current,
      getHideHomeOnly: () => hideHomeOnlyRef.current,
      getTargetPathFilter: () => targetPathFilterRef.current,
      getSelectedHistoryEventId: () => selectedHistoryEventIdRef.current,
      getRequestedHop: () => requestedHopRef.current,
      getExpiredSessionId: () => expiredSessionIdRef.current,
      getSnapshot: () => snapshot,
      getExtraAuditSessions: () => extraAuditSessions,
      setExtraAuditSessions: options.setExtraAuditSessions,

      setViewMode,
      setHideHomeOnly,
      setTargetPathFilter,
      setSelectedHistoryEventId,
      setExpiredSessionId,
      setSelectedSessionId: (id) => {
        activeSessionIdRef.current = id;
        setSelectedSessionId?.(id);
      },
      setRequestedHop: (hop) => {
        requestedHopRef.current = hop;
      },
      setRequestedSessionId: (sid) => {
        requestedSessionIdRef.current = sid;
      },
    });
  }, [
    navigationCoordinator,
    snapshot,
    extraAuditSessions,
    options.setExtraAuditSessions,
    setViewMode,
    setHideHomeOnly,
    setTargetPathFilter,
    setSelectedHistoryEventId,
    setExpiredSessionId,
    setSelectedSessionId,
    activeSessionIdRef,
  ]);

  const commitUserNavigation = useCallback(
    (updates: NavigationStateCommitOptions) => {
      navigationCoordinator.commit(updates, "push");
    },
    [navigationCoordinator],
  );

  const commitPlaybackNavigation = useCallback(
    (hopId: string | null) => {
      navigationCoordinator.playbackSelectHop(hopId);
    },
    [navigationCoordinator],
  );

  const switchViewMode = useCallback(
    (mode: "live" | "audit", targetSessionId?: string) => {
      navigationCoordinator.userSelectViewMode(mode, targetSessionId);
    },
    [navigationCoordinator],
  );

  // Listen for browser Back and Forward navigation (popstate)
  useEffect(() => {
    if (typeof window === "undefined") return;
    const handlePopState = () => {
      navigationCoordinator.handlePopState(window.location.search);
    };

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, [navigationCoordinator]);

  // Synchronize React navigation & filter state with the URL for initial hydration and system-driven fallbacks
  // Guarded against overwriting pending popstate targets with stale pre-navigation React state
  useEffect(() => {
    if (!isHydrated || typeof window === "undefined") return;
    navigationCoordinator.synchronizeUrlState();
  }, [
    isHydrated,
    viewMode,
    selectedSessionId,
    expiredSessionId,
    hideHomeOnly,
    targetPathFilter,
    selectedHistoryEventId,
    navigationCoordinator,
  ]);

  return {
    viewMode,
    setViewMode,
    viewModeRef,
    switchViewMode,
    hideHomeOnly,
    setHideHomeOnly,
    targetPathFilter,
    setTargetPathFilter,
    selectedHistoryEventId,
    setSelectedHistoryEventId,
    expiredSessionId,
    setExpiredSessionId,
    requestedHopRef,
    requestedSessionIdRef,
    commitUserNavigation,
    commitPlaybackNavigation,
    navigationCoordinator,
  };
}

export interface ProcessAuditPopStateParams {
  search: string;
  snapshot: FilesystemTopologySnapshot | null;
  extraAuditSessions: Map<string, FilesystemClosedSession | FilesystemTopologySession>;
  coordinator?: RemoteAuditLookupCoordinator | null;
  lookupRemoteAuditSession: (intent: {
    sessionId: string;
    targetHopId?: string | null;
  }) => Promise<void> | void;
  selectSession: (
    sessionId: string,
    sessionObj?: FilesystemTopologySession | FilesystemClosedSession,
    targetHopId?: string | null,
  ) => void;
  setViewMode: (mode: "live" | "audit") => void;
  viewModeRef?: { current: "live" | "audit" };
  setHideHomeOnly: (hide: boolean) => void;
  setTargetPathFilter: (path: string | null) => void;
  setSelectedHistoryEventId: (eventId: string | null) => void;
  setExpiredSessionId: (id: string | null) => void;
  requestedHopRef: { current: string | null };
  requestedSessionIdRef: { current: string | null };
  selectedSessionIdRef: { current: string | null };
  setSelectedSessionId?: (id: string | null) => void;
}

/**
 * @deprecated Legacy standalone popstate processor from FA-005.
 * Production navigation now routes exclusively through FilesystemNavigationCoordinator.
 * Retained for backwards compatibility with FA-005 test harnesses.
 */
export function processAuditPopState(params: ProcessAuditPopStateParams): void {
  const parsed = parseAuditUrlParams(params.search);
  const nextView = parsed.view ?? "live";
  const effectiveHop = nextView === "live" ? null : (parsed.hop ?? null);

  params.coordinator?.notifyNavigationScope({
    viewMode: nextView,
    sessionId: parsed.sessionId ?? null,
    targetHopId: effectiveHop,
  });
  params.setViewMode(nextView);
  if (params.viewModeRef) {
    params.viewModeRef.current = nextView;
  }
  params.setHideHomeOnly(Boolean(parsed.hideHome));
  params.setTargetPathFilter(parsed.targetPath ?? null);
  params.requestedHopRef.current = effectiveHop;
  params.setSelectedHistoryEventId(effectiveHop);

  if (parsed.sessionId) {
    params.requestedSessionIdRef.current = parsed.sessionId;
    if (params.snapshot) {
      const known = [
        ...params.snapshot.sessions,
        ...params.snapshot.recentClosedSessions,
        ...params.extraAuditSessions.values(),
      ];
      const resolution = resolveSessionSelection(
        parsed.sessionId,
        null,
        known,
        nextView === "audit",
      );
      if (resolution.expiredSessionId) {
        if (nextView === "audit") {
          void params.lookupRemoteAuditSession({
            sessionId: resolution.expiredSessionId,
            targetHopId: effectiveHop,
          });
        } else {
          params.setExpiredSessionId(resolution.expiredSessionId);
          params.selectedSessionIdRef.current = null;
          params.setSelectedSessionId?.(null);
        }
      } else {
        params.setExpiredSessionId(null);
        if (resolution.sessionId) {
          params.selectSession(resolution.sessionId, undefined, effectiveHop);
        }
      }
    } else {
      params.selectedSessionIdRef.current = parsed.sessionId;
      params.setSelectedSessionId?.(parsed.sessionId);
    }
  } else {
    params.requestedSessionIdRef.current = null;
    params.setExpiredSessionId(null);
    if (nextView === "audit") {
      params.selectedSessionIdRef.current = null;
      params.setSelectedSessionId?.(null);
    }
  }
}

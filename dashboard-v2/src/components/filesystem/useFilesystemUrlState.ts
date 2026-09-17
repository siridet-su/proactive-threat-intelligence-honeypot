"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
} from "@/lib/dashboardTypes";
import {
  type AuditUrlParams,
  areAuditUrlParamsEqual,
  buildAuditTargetUrl,
  buildAuditUrlSearch,
  parseAuditUrlParams,
  resolveSessionSelection,
} from "./filesystemUtils";
import type {
  RemoteAuditLookupCoordinator,
  RemoteAuditLookupIntent,
} from "./sessionHopResolver";

export interface NavigationStateCommitOptions {
  view?: "live" | "audit";
  sessionId?: string | null;
  hideHome?: boolean;
  targetPath?: string | null;
  hop?: string | null;
}

export interface UseFilesystemUrlStateOptions {
  isHydrated: boolean;
  snapshot: FilesystemTopologySnapshot | null;
  extraAuditSessions: Map<string, FilesystemClosedSession | FilesystemTopologySession>;
  selectedSessionId: string | null;
  selectedSessionIdRef: React.MutableRefObject<string | null>;
  selectSession: (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession, targetHopId?: string | null) => void;
  lookupRemoteAuditSession: (target: RemoteAuditLookupIntent | string, targetHopId?: string | null) => Promise<void> | void;
  coordinator?: RemoteAuditLookupCoordinator;
  setSelectedSessionId?: (id: string | null) => void;
  onExitFullscreenAndPlaying?: () => void;
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
  isUserNavigatingRef: React.MutableRefObject<boolean>;
  commitUserNavigation: (updates: NavigationStateCommitOptions) => void;
  commitPlaybackNavigation: (hopId: string | null) => void;
}

export function useFilesystemUrlState(
  options: UseFilesystemUrlStateOptions,
): UseFilesystemUrlStateReturn {
  const {
    isHydrated,
    snapshot,
    extraAuditSessions,
    selectedSessionId,
    selectedSessionIdRef,
    selectSession,
    lookupRemoteAuditSession,
    coordinator,
    setSelectedSessionId,
    onExitFullscreenAndPlaying,
  } = options;

  const [viewMode, setViewMode] = useState<"live" | "audit">(() => {
    if (typeof window === "undefined") return "live";
    const parsed = parseAuditUrlParams(window.location.search);
    return parsed.view === "audit" ? "audit" : "live";
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
  const [expiredSessionId, setExpiredSessionId] = useState<string | null>(null);

  const initialParsed = typeof window !== "undefined" ? parseAuditUrlParams(window.location.search) : null;
  const viewModeRef = useRef<"live" | "audit">(viewMode);
  const hideHomeOnlyRef = useRef<boolean>(hideHomeOnly);
  const targetPathFilterRef = useRef<string | null>(targetPathFilter);
  const selectedHistoryEventIdRef = useRef<string | null>(selectedHistoryEventId);
  const expiredSessionIdRef = useRef<string | null>(expiredSessionId);
  const requestedSessionIdRef = useRef<string | null>(initialParsed?.sessionId ?? null);
  const requestedHopRef = useRef<string | null>(initialParsed?.hop ?? null);
  const isUserNavigatingRef = useRef(false);
  const isPopStateActiveRef = useRef(false);

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
    expiredSessionIdRef.current = expiredSessionId;
  }, [expiredSessionId]);

  useEffect(() => {
    if (requestedSessionIdRef.current) {
      selectedSessionIdRef.current = requestedSessionIdRef.current;
    }
  }, [selectedSessionIdRef]);

  const commitUserNavigation = useCallback(
    (updates: NavigationStateCommitOptions) => {
      if (typeof window === "undefined") return;

      const currentParams = parseAuditUrlParams(window.location.search);
      const targetView = updates.view ?? viewModeRef.current;
      const targetHop =
        targetView === "live"
          ? null
          : updates.hop !== undefined
            ? updates.hop
            : (selectedHistoryEventIdRef.current ?? requestedHopRef.current);

      const targetParams: AuditUrlParams = {
        view: targetView,
        sessionId:
          updates.sessionId !== undefined
            ? updates.sessionId
            : (selectedSessionIdRef.current ?? expiredSessionIdRef.current),
        hideHome: updates.hideHome !== undefined ? updates.hideHome : hideHomeOnlyRef.current,
        targetPath:
          updates.targetPath !== undefined
            ? updates.targetPath
            : targetPathFilterRef.current,
        hop: targetHop,
      };

      const currentSearch = window.location.search;
      const targetSearch = buildAuditUrlSearch(targetParams);

      if (currentSearch === targetSearch && areAuditUrlParamsEqual(currentParams, targetParams)) {
        return;
      }

      const targetUrl = buildAuditTargetUrl(targetParams);
      window.history.pushState(null, "", targetUrl);
    },
    [requestedHopRef, selectedSessionIdRef],
  );

  const commitPlaybackNavigation = useCallback(
    (hopId: string | null) => {
      if (typeof window === "undefined") return;

      const currentParams = parseAuditUrlParams(window.location.search);
      const targetParams: AuditUrlParams = {
        view: "audit",
        sessionId: selectedSessionIdRef.current ?? expiredSessionIdRef.current,
        hideHome: hideHomeOnlyRef.current,
        targetPath: targetPathFilterRef.current,
        hop: hopId,
      };

      const currentSearch = window.location.search;
      const targetSearch = buildAuditUrlSearch(targetParams);

      if (currentSearch === targetSearch && areAuditUrlParamsEqual(currentParams, targetParams)) {
        return;
      }

      const targetUrl = buildAuditTargetUrl(targetParams);
      window.history.replaceState(null, "", targetUrl);
    },
    [selectedSessionIdRef],
  );

  const switchViewMode = useCallback(
    (mode: "live" | "audit", targetSessionId?: string) => {
      if (mode === "live") {
        onExitFullscreenAndPlaying?.();
      }
      isUserNavigatingRef.current = true;
      viewModeRef.current = mode;
      setViewMode(mode);
      setExpiredSessionId(null);
      const sid =
        targetSessionId ??
        selectedSessionIdRef.current ??
        snapshot?.sessions[0]?.sessionId ??
        snapshot?.recentClosedSessions[0]?.sessionId ??
        null;

      if (mode === "live") {
        requestedHopRef.current = null;
        setSelectedHistoryEventId(null);
        coordinator?.notifyNavigationScope({
          viewMode: "live",
          sessionId: sid,
          targetHopId: null,
        });
        commitUserNavigation({
          view: "live",
          sessionId: sid,
          hop: null,
        });
      } else {
        coordinator?.notifyNavigationScope({
          viewMode: "audit",
          sessionId: sid,
          targetHopId: null,
        });
        commitUserNavigation({
          view: "audit",
          sessionId: sid,
          hop: null,
        });
        if (sid) {
          selectSession(sid);
        }
      }
    },
    [
      commitUserNavigation,
      coordinator,
      onExitFullscreenAndPlaying,
      requestedHopRef,
      selectSession,
      selectedSessionIdRef,
      setSelectedHistoryEventId,
      snapshot?.recentClosedSessions,
      snapshot?.sessions,
    ],
  );

  // Listen for browser Back and Forward navigation (popstate)
  useEffect(() => {
    if (typeof window === "undefined") return;
    const handlePopState = () => {
      isPopStateActiveRef.current = true;
      try {
        processAuditPopState({
          search: window.location.search,
          snapshot,
          extraAuditSessions,
          coordinator,
          lookupRemoteAuditSession: (intent) => lookupRemoteAuditSession(intent),
          selectSession,
          setViewMode,
          viewModeRef,
          setHideHomeOnly,
          setTargetPathFilter,
          setSelectedHistoryEventId,
          setExpiredSessionId,
          requestedHopRef,
          requestedSessionIdRef,
          selectedSessionIdRef,
          setSelectedSessionId,
        });
      } finally {
        queueMicrotask(() => {
          isPopStateActiveRef.current = false;
        });
      }
    };

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, [
    coordinator,
    snapshot,
    selectSession,
    lookupRemoteAuditSession,
    extraAuditSessions,
    selectedSessionIdRef,
    setSelectedSessionId,
    requestedHopRef,
    requestedSessionIdRef,
    viewModeRef,
  ]);

  // Synchronize React navigation & filter state with the URL for initial hydration and system-driven fallbacks
  useEffect(() => {
    if (!isHydrated || typeof window === "undefined") return;
    if (isPopStateActiveRef.current) return;

    const currentParams = parseAuditUrlParams(window.location.search);
    const currentSession = selectedSessionId ?? expiredSessionId;
    const targetParams: AuditUrlParams = {
      view: viewMode,
      sessionId: currentSession,
      hideHome: hideHomeOnly,
      targetPath: targetPathFilter,
      hop: viewMode === "live" ? null : (selectedHistoryEventId ?? requestedHopRef.current),
    };

    const currentSearch = window.location.search;
    const targetSearch = buildAuditUrlSearch(targetParams);

    if (currentSearch !== targetSearch || !areAuditUrlParamsEqual(currentParams, targetParams)) {
      const targetUrl = buildAuditTargetUrl(targetParams);
      // Automatic sync and hydration canonicalization use replaceState, never pushState
      window.history.replaceState(null, "", targetUrl);
    }
  }, [
    isHydrated,
    viewMode,
    selectedSessionId,
    expiredSessionId,
    hideHomeOnly,
    targetPathFilter,
    selectedHistoryEventId,
    requestedHopRef,
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
    isUserNavigatingRef,
    commitUserNavigation,
    commitPlaybackNavigation,
  };
}

export interface ProcessAuditPopStateParams {
  search: string;
  snapshot: FilesystemTopologySnapshot | null;
  extraAuditSessions: Map<string, FilesystemClosedSession | FilesystemTopologySession>;
  coordinator?: RemoteAuditLookupCoordinator | null;
  lookupRemoteAuditSession: (intent: { sessionId: string; targetHopId?: string | null }) => Promise<void> | void;
  selectSession: (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession, targetHopId?: string | null) => void;
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
      const resolution = resolveSessionSelection(parsed.sessionId, null, known, nextView === "audit");
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

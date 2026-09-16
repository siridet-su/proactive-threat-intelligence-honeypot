"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import type {
  FilesystemClosedSession,
  FilesystemTopologySession,
  FilesystemTopologySnapshot,
} from "@/lib/dashboardTypes";
import {
  buildAuditUrlSearch,
  parseAuditUrlParams,
  resolveSessionSelection,
} from "./filesystemUtils";

export interface UseFilesystemUrlStateOptions {
  isHydrated: boolean;
  snapshot: FilesystemTopologySnapshot | null;
  extraAuditSessions: Map<string, FilesystemClosedSession | FilesystemTopologySession>;
  selectedSessionId: string | null;
  selectedSessionIdRef: React.MutableRefObject<string | null>;
  selectSession: (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession) => void;
  lookupRemoteAuditSession: (targetId: string) => Promise<void>;
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
  const requestedSessionIdRef = useRef<string | null>(initialParsed?.sessionId ?? null);
  const requestedHopRef = useRef<string | null>(initialParsed?.hop ?? null);
  const isUserNavigatingRef = useRef(false);

  useEffect(() => {
    viewModeRef.current = viewMode;
  }, [viewMode]);

  useEffect(() => {
    if (requestedSessionIdRef.current) {
      selectedSessionIdRef.current = requestedSessionIdRef.current;
    }
  }, [selectedSessionIdRef]);

  const switchViewMode = useCallback(
    (mode: "live" | "audit", targetSessionId?: string) => {
      if (mode === "live") {
        onExitFullscreenAndPlaying?.();
      }
      isUserNavigatingRef.current = true;
      setViewMode(mode);
      setExpiredSessionId(null);
      const sid =
        targetSessionId ??
        selectedSessionIdRef.current ??
        snapshot?.sessions[0]?.sessionId ??
        snapshot?.recentClosedSessions[0]?.sessionId ??
        null;
      if (sid) {
        selectSession(sid);
      }
    },
    [onExitFullscreenAndPlaying, selectSession, selectedSessionIdRef, snapshot?.recentClosedSessions, snapshot?.sessions],
  );

  // Listen for browser Back and Forward navigation (popstate)
  useEffect(() => {
    if (typeof window === "undefined") return;
    const handlePopState = () => {
      const parsed = parseAuditUrlParams(window.location.search);
      setViewMode(parsed.view ?? "live");
      setHideHomeOnly(Boolean(parsed.hideHome));
      setTargetPathFilter(parsed.targetPath ?? null);
      requestedHopRef.current = parsed.hop ?? null;
      setSelectedHistoryEventId(parsed.hop ?? null);

      if (parsed.sessionId) {
        requestedSessionIdRef.current = parsed.sessionId;
        if (snapshot) {
          const known = [
            ...snapshot.sessions,
            ...snapshot.recentClosedSessions,
            ...extraAuditSessions.values(),
          ];
          const resolution = resolveSessionSelection(parsed.sessionId, null, known, parsed.view === "audit");
          if (resolution.expiredSessionId) {
            if (parsed.view === "audit") {
              void lookupRemoteAuditSession(resolution.expiredSessionId);
            } else {
              setExpiredSessionId(resolution.expiredSessionId);
              selectedSessionIdRef.current = null;
              setSelectedSessionId?.(null);
            }
          } else {
            setExpiredSessionId(null);
            if (resolution.sessionId) selectSession(resolution.sessionId);
          }
        } else {
          selectedSessionIdRef.current = parsed.sessionId;
          setSelectedSessionId?.(parsed.sessionId);
        }
      } else {
        requestedSessionIdRef.current = null;
        setExpiredSessionId(null);
        if (parsed.view === "audit") {
          selectedSessionIdRef.current = null;
          setSelectedSessionId?.(null);
        }
      }
    };

    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, [snapshot, selectSession, lookupRemoteAuditSession, extraAuditSessions, selectedSessionIdRef, setSelectedSessionId]);

  // Synchronize React navigation & filter state with the URL
  useEffect(() => {
    if (!isHydrated || typeof window === "undefined") return;

    const currentSession = selectedSessionId ?? expiredSessionId;
    const search = buildAuditUrlSearch({
      view: viewMode,
      sessionId: currentSession,
      hideHome: hideHomeOnly,
      targetPath: targetPathFilter,
      hop: selectedHistoryEventId,
    });

    const currentSearch = window.location.search;
    if (search !== currentSearch) {
      const targetUrl = `${window.location.pathname}${search}${window.location.hash}`;
      if (isUserNavigatingRef.current) {
        window.history.pushState(null, "", targetUrl);
        isUserNavigatingRef.current = false;
      } else {
        window.history.replaceState(null, "", targetUrl);
      }
    }
  }, [
    isHydrated,
    viewMode,
    selectedSessionId,
    expiredSessionId,
    hideHomeOnly,
    targetPathFilter,
    selectedHistoryEventId,
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
  };
}

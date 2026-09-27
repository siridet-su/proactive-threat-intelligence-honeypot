"use client";

import {
  History,
  Terminal,
} from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { useCallback, useEffect, useRef, useState, type KeyboardEvent } from "react";

import { ReplayTransport } from "./ReplayTransport";
import { RouteEventList } from "./RouteEventList";
import { CommandEvidencePanel } from "./CommandEvidencePanel";
import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { FilesystemTopologySession, SessionCwdHistoryEvent } from "@/lib/dashboardTypes";
import {
  isReplayTimelineKeyboardKey,
  mapReplayTimelineKeyToIndex,
} from "./filesystemUtils";
import type { HopResolutionStatus } from "./sessionHopResolver";
import type { AuditReplayPresentation } from "./useAuditReplay";
import { handleRovingTabKey } from "./tabSemantics";

type SidebarTab = "replay" | "evidence";

const SIDEBAR_TAB_COLUMN: Record<SidebarTab, number> = {
  replay: 1,
  evidence: 2,
};

const SIDEBAR_TABS = [
  { id: "replay", label: "Route Replay", icon: null },
  { id: "evidence", label: "Evidence", icon: Terminal },
] as const;

const SIDEBAR_TAB_IDS = SIDEBAR_TABS.map((tab) => tab.id);

const SIDEBAR_CONTENT_VARIANTS = {
  enter: (direction: number) => ({ opacity: direction === 0 ? 1 : 0, x: direction * 10 }),
  center: { opacity: 1, x: 0 },
  exit: (direction: number) => ({ opacity: direction === 0 ? 1 : 0, x: direction * -6 }),
};

export interface CwdRouteHistoryProps {
  selectedSession: FilesystemTopologySession | null;
  history: SessionCwdHistoryEvent[];
  anchoredHop?: SessionCwdHistoryEvent | null;
  historyStatus: RegionStatus;
  historyCursor: string | null;
  historyTotalItems: number;
  historyTotalSuccessfulItems: number;
  historyComplete: boolean;
  replay: AuditReplayPresentation;
  layout?: "card" | "sidebar";
  activeTab: SidebarTab;
  onTabChange: (tab: SidebarTab) => void;
  hopResolutionStatus?: HopResolutionStatus;
  requestedHop?: string | null;
  onClearHop: () => void;
  onShowLatestHop: () => void;
  onSelectHistoryEventId: (eventId: string | null, source?: "user" | "playback" | "sync") => void;
  onLoadEarlier: () => void;
  isDragging?: boolean;
}

export function CwdRouteHistory({
  selectedSession,
  history,
  anchoredHop = null,
  historyStatus,
  historyCursor,
  historyTotalItems,
  historyTotalSuccessfulItems,
  historyComplete,
  replay,
  layout = "card",
  activeTab: controlledSidebarTab,
  onTabChange,
  hopResolutionStatus = "idle",
  requestedHop = null,
  onClearHop,
  onShowLatestHop,
  onSelectHistoryEventId,
  onLoadEarlier,
  isDragging,
}: CwdRouteHistoryProps) {
  const [sidebarTabDirection, setSidebarTabDirection] = useState(1);
  const shouldReduceMotion = useReducedMotion();
  const isSidebar = layout === "sidebar";
  const sidebarTab = controlledSidebarTab;
  const {
    isPlaying,
    playbackSpeed,
    pacingMode,
    displayedHistory,
    selectedHistoryIndex,
    displayedHistoryMetrics,
    isAnchoredSelected,
    hopTimeMetrics,
    sessionTimeSummary,
    replayTimeline,
    onTogglePlay,
    onPause,
    onToggleSpeed,
    onTogglePacingMode,
    showFailedAttempts,
    onToggleShowFailedAttempts,
  } = replay;
  const failedCount = Math.max(0, historyTotalItems - historyTotalSuccessfulItems);

  const selectedHistoryEvent = isAnchoredSelected
    ? anchoredHop
    : selectedHistoryIndex >= 0
      ? displayedHistory[selectedHistoryIndex]
      : null;

  const timeMetrics = { hopMetrics: hopTimeMetrics, summary: sessionTimeSummary };

  const activeHistoryEventId = selectedHistoryEvent?.id ?? null;
  const isFailedHop = selectedHistoryEvent?.action === "failed_change";

  const timelineContainerRef = useRef<HTMLDivElement | null>(null);
  const activeItemRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!activeHistoryEventId) return;
    const container = timelineContainerRef.current;
    const item = activeItemRef.current;
    if (container && item) {
      const containerRect = container.getBoundingClientRect();
      const itemRect = item.getBoundingClientRect();
      const relativeItemTop = itemRect.top - containerRect.top + container.scrollTop;
      const targetScrollTop = relativeItemTop - (container.clientHeight / 2) + (itemRect.height / 2);

      container.scrollTo({
        top: Math.max(0, targetScrollTop),
        behavior: "smooth",
      });
    }
  }, [activeHistoryEventId]);

  const handlePause = useCallback(() => {
    onPause();
  }, [onPause]);

  const selectDisplayedHistoryIndex = useCallback((targetIndex: number) => {
    if (isAnchoredSelected || targetIndex < 0 || targetIndex >= displayedHistory.length || targetIndex === selectedHistoryIndex) return;
    const targetEvent = displayedHistory[targetIndex];
    if (!targetEvent) return;
    handlePause();
    onSelectHistoryEventId(targetEvent.id);
  }, [displayedHistory, handlePause, isAnchoredSelected, onSelectHistoryEventId, selectedHistoryIndex]);

  const handleScrubberKeyDown = useCallback((event: KeyboardEvent<HTMLInputElement>) => {
    if (isAnchoredSelected || !isReplayTimelineKeyboardKey(event.key)) return;
    event.preventDefault();
    const targetIndex = mapReplayTimelineKeyToIndex(event.key, selectedHistoryIndex, displayedHistory.length);
    if (targetIndex !== null) selectDisplayedHistoryIndex(targetIndex);
  }, [displayedHistory.length, isAnchoredSelected, selectDisplayedHistoryIndex, selectedHistoryIndex]);

  const handleTogglePlay = useCallback(() => {
    onTogglePlay();
  }, [onTogglePlay]);

  const sidebarTabColumn = SIDEBAR_TAB_COLUMN[sidebarTab];
  const sidebarContentDirection = shouldReduceMotion ? 0 : sidebarTabDirection;

  const handleSidebarTabChange = (nextTab: SidebarTab) => {
    if (nextTab === sidebarTab) return;
    setSidebarTabDirection(SIDEBAR_TAB_COLUMN[nextTab] > sidebarTabColumn ? 1 : -1);
    onTabChange(nextTab);
  };

  const handleSidebarTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>, currentTab: SidebarTab) => {
    handleRovingTabKey({
      event,
      tabs: SIDEBAR_TAB_IDS,
      currentTab,
      onSelect: handleSidebarTabChange,
      tabId: (tab) => `tab-${tab}`,
    });
  };

  return (
    <div className={`ui-panel overflow-hidden ${isSidebar ? "flex flex-col h-full min-h-0" : ""}`}>
      {/* Panel Header with Compact Tabs */}
      <div
        className={`flex shrink-0 gap-2 border-b border-border px-3.5 py-2.5 ${
          isSidebar ? "flex-col" : "flex-col sm:flex-row sm:items-center sm:justify-between"
        }`}
      >
        <div className={`min-w-0 ${isSidebar ? "flex flex-col gap-2" : "flex items-center gap-2"}`}>
          <div className="flex min-w-0 items-center gap-2">
            <History className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            <h2 className="truncate text-xs font-semibold sm:text-sm">
              {isSidebar ? "Forensic Studio" : "Verified CWD route"}
            </h2>
          </div>
          {isSidebar && (
            <div
              className="relative isolate grid w-full grid-cols-2 gap-1 rounded-lg border border-border bg-surface-subtle p-0.5 text-xs"
              role="tablist"
              aria-label="Forensic studio views"
            >
              <div aria-hidden="true" className="pointer-events-none absolute inset-0.5 grid grid-cols-2 gap-1">
                <motion.span
                  layout="position"
                  data-forensic-tab-highlight
                  className="rounded-md border border-border bg-surface shadow-2xs"
                  style={{ gridColumnStart: sidebarTabColumn }}
                  transition={
                    shouldReduceMotion || isDragging
                      ? { duration: 0 }
                      : { duration: 0.28, ease: [0.4, 0, 0.2, 1] }
                  }
                />
              </div>
              {SIDEBAR_TABS.map((tab) => {
                const isActive = sidebarTab === tab.id;
                const Icon = tab.icon;

                return (
                  <button
                    key={tab.id}
                    type="button"
                    role="tab"
                    id={`tab-${tab.id}`}
                    aria-selected={isActive}
                    aria-controls={`tabpanel-${tab.id}`}
                    tabIndex={isActive ? 0 : -1}
                    onClick={() => handleSidebarTabChange(tab.id)}
                    onKeyDown={(event) => handleSidebarTabKeyDown(event, tab.id)}
                    className={`relative z-10 flex min-h-9 cursor-pointer items-center justify-center gap-1 rounded-md border border-transparent px-2 text-xs font-medium transition-colors duration-300 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus-ring ${
                      isActive ? "text-primary" : "text-text-muted hover:text-text"
                    }`}
                  >
                    {Icon && <Icon className="h-3 w-3" aria-hidden="true" />}
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
        {selectedSession && !isSidebar && (
          <span className="ui-badge shrink-0 font-mono text-xs whitespace-nowrap hidden sm:inline-flex py-0.5 px-2">
            {selectedSession.sessionId.slice(0, 8)}…
          </span>
        )}
      </div>

      <div className={`p-3 ${isSidebar ? "flex flex-1 flex-col min-h-0 overflow-hidden" : ""}`}>
        {!selectedSession ? (
          <RegionState
            kind="empty"
            title="Select a session to inspect its path history"
            description="Choose a session from the topology or inspector."
          />
        ) : (
          <>
            {/* Hop resolution feedback alert for unavailable, missing, or cross-session hops */}
            {(hopResolutionStatus === "not-found" || hopResolutionStatus === "error") && (
              <div
                role="alert"
                className="mb-2.5 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200"
                data-testid="hop-resolution-banner"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <p className="font-semibold text-amber-100">
                      {hopResolutionStatus === "not-found"
                        ? "Requested hop unavailable"
                        : "Error resolving requested hop"}
                    </p>
                    <p className="mt-0.5 text-amber-200/80">
                      {hopResolutionStatus === "not-found"
                        ? `The requested hop "${requestedHop}" could not be found or has expired.`
                        : `Could not retrieve hop "${requestedHop}".`}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-1.5">
                    {history.length > 0 && (
                      <button
                        type="button"
                        onClick={onShowLatestHop}
                        className="rounded bg-amber-500/20 px-2.5 py-1 font-medium text-amber-100 hover:bg-amber-500/30 transition-colors"
                      >
                        Show latest hop
                      </button>
                    )}
                    <button
                        type="button"
                        onClick={onClearHop}
                        className="rounded border border-amber-500/40 px-2.5 py-1 font-medium text-amber-200 hover:bg-amber-500/20 transition-colors"
                      >
                        Clear hop
                    </button>
                  </div>
                </div>
              </div>
            )}

            {!isSidebar && historyStatus === "error" && !history.length ? (
              <RegionState
                kind="error"
                title="Session history unavailable"
                description="The selected CWD history could not be loaded."
              />
            ) : !isSidebar && historyStatus === "loading" && !history.length ? (
              <RegionState kind="loading" title="Loading session history" />
            ) : !isSidebar && !history.length ? (
              <RegionState
                kind="empty"
                title="No verified directory transitions"
                description="This session has a known observed path, but Cowrie has not recorded a directory move. It may have ended after a non-interactive probe."
              />
            ) : (
              <AnimatePresence initial={false} mode="popLayout" custom={sidebarContentDirection}>
            <motion.div
              key={isSidebar ? sidebarTab : "route-history"}
              data-forensic-tab-panel={sidebarTab}
              role="tabpanel"
              id={`tabpanel-${sidebarTab}`}
              aria-labelledby={`tab-${sidebarTab}`}
              custom={sidebarContentDirection}
              variants={SIDEBAR_CONTENT_VARIANTS}
              initial={isSidebar ? "enter" : false}
              animate="center"
              exit={isSidebar ? "exit" : undefined}
              transition={
                shouldReduceMotion
                  ? { duration: 0 }
                  : { duration: 0.18, ease: [0.4, 0, 0.2, 1] }
              }
              className={isSidebar ? "flex min-h-0 flex-1 flex-col" : undefined}
            >
              {sidebarTab === "evidence" ? (
                <CommandEvidencePanel key={selectedSession.sessionId} selectedSession={selectedSession} />
              ) : (
                /* Tab 1: Route Replay with alert support */
                <>

                  {historyStatus === "error" && !history.length ? (
                    <RegionState
                      kind="error"
                      title="Session history unavailable"
                      description="Route Replay could not load this session's CWD transitions. Evidence loads retained Cowrie command events separately when the protected source is available."
                    />
                  ) : historyStatus === "loading" && !history.length ? (
                    <RegionState kind="loading" title="Loading session history" />
                  ) : !history.length ? (
                    <RegionState
                      kind="empty"
                      title="No verified directory transitions"
                      description="This session has a known observed path, but Cowrie has not recorded a directory move."
                    />
                  ) : (
                    <>
                      <ReplayTransport
                        isAnchoredSelected={isAnchoredSelected}
                        historyComplete={historyComplete}
                        onLoadEarlier={onLoadEarlier}
                        selectedHistoryIndex={selectedHistoryIndex}
                        displayedHistoryLength={displayedHistory.length}
                        selectDisplayedHistoryIndex={selectDisplayedHistoryIndex}
                        handleTogglePlay={handleTogglePlay}
                        isPlaying={isPlaying}
                        onToggleSpeed={onToggleSpeed}
                        playbackSpeed={playbackSpeed}
                        onTogglePacingMode={onTogglePacingMode}
                        pacingMode={pacingMode}
                        failedCount={failedCount}
                        showFailedAttempts={showFailedAttempts}
                        onToggleShowFailedAttempts={onToggleShowFailedAttempts}
                        displayedHistoryMetrics={displayedHistoryMetrics}
                        timeMetrics={timeMetrics}
                        replayTimeline={replayTimeline}
                        handleScrubberKeyDown={handleScrubberKeyDown}
                        isFailedHop={isFailedHop}
                        selectedHistoryEvent={selectedHistoryEvent}
                      />
                      <RouteEventList
                        historyComplete={historyComplete}
                        historyCursor={historyCursor}
                        historyStatus={historyStatus}
                        historyLength={history.length}
                        historyTotalItems={historyTotalItems}
                        replayTimeline={replayTimeline}
                        onLoadEarlier={onLoadEarlier}
                        timelineContainerRef={timelineContainerRef}
                        isSidebar={isSidebar}
                        displayedHistory={displayedHistory}
                        activeHistoryEventId={activeHistoryEventId}
                        timeMetrics={timeMetrics}
                        activeItemRef={activeItemRef}
                        handlePause={handlePause}
                        onSelectHistoryEventId={onSelectHistoryEventId}
                        displayedHistoryMetrics={displayedHistoryMetrics}
                        anchoredHop={anchoredHop}
                        isAnchoredSelected={isAnchoredSelected}
                        showFailedAttempts={showFailedAttempts}
                      />
          </>
        )}
      </>
    )}
  </motion.div>
          </AnimatePresence>
        )}
          </>
        )}
      </div>
    </div>
  );
}

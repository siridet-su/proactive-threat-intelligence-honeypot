/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState } from "react";
import { AuditScopeBar } from "./AuditScopeBar";
import { AuditNoticeRegion } from "./AuditNoticeRegion";
import { TopologyCanvas } from "./TopologyCanvas";
import { TimelineSplitter } from "./TimelineSplitter";
import { FilesystemTimelinePanel } from "./FilesystemTimelinePanel";
import { DEFAULT_STALE_THRESHOLD_MS } from "./filesystemUtils";
import type { FilesystemClosedSession, FilesystemTopologySession, FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import type { ForensicTab } from "./FilesystemActivity";

export interface AuditFilesystemWorkspaceProps {
  directoryHasMore: boolean;
  directoryIsLoading: boolean;
  directoryIsComplete: boolean;
  loadMoreDirectory: () => void;
  auditSearchItems: any[];
  auditSearchHasMore: boolean;
  auditSearchIsLoading: boolean;
  auditSearchIsComplete: boolean;
  searchAuditSessions: (q: string) => void;
  loadMoreAuditSearch: () => void;
  clearAuditSearch: () => void;
  auditStatus: any;
  auditErrorMessage: any;
  retryInitialDirectory: () => void;
  handleToggleHideHomeOnly: () => void;
  handleSelectTargetPath: (path: string | null) => void;
  distinctPaths: any;
  homeOnlyCount: number;

  isFullscreen: boolean;
  expiredSessionId: string | null;
  allSessions: any[];
  setExpiredSessionId: (id: string | null) => void;
  handleUserSelectSession: (sessionId: string, sessionObj?: FilesystemTopologySession | FilesystemClosedSession) => void;
  switchViewMode: (mode: "live" | "audit", sessionId?: string) => void;
  hasActiveFilters: boolean;
  isSelectedFilteredOut: boolean;
  filteredSessionsCount: number;
  totalSessionsCount: number;
  targetPathFilter: string | null;
  hideHomeOnly: boolean;
  selectedSession: FilesystemClosedSession | FilesystemTopologySession | null;
  filteredActiveSessions: FilesystemTopologySession[];
  filteredClosedSessions: FilesystemClosedSession[];
  handleResetAuditFilters: () => void;
  handleClearSelection: () => void;
  auditSnapshot: FilesystemTopologySnapshot | null;
  snapshot: FilesystemTopologySnapshot | null;
  regionStatus: any;
  streamState: any;
  freshnessState: any;
  selectedSessionId: string | null;
  selectedPath: string | null;
  activeHop: any;
  playbackSpeed: number;
  auditCanvasTitle: string;
  auditCanvasSubtitle: string;
  selectPath: (path: string | null) => void;
  onToggleFullscreen: () => void;
  refresh: () => void;
  handleReconnect: () => void;
  isDraggingTimeline: boolean;
  isTimelineCollapsed: boolean;
  timelineWidth: number;
  handleSplitterMouseDown: (e: React.MouseEvent) => void;
  handleResetTimelineWidth: () => void;
  handleSplitterKeyDown: (e: React.KeyboardEvent) => void;
  history: any;
  anchoredHop: any;
  historyStatus: any;
  historyCursor: any;
  historyTotalItems: number;
  historyTotalSuccessfulItems: number;
  historyComplete: boolean;
  replayPresentation: any;
  activeForensicTab: ForensicTab;
  setActiveForensicTab: (tab: ForensicTab) => void;
  responsePanel: React.ReactNode;
  hopResolutionStatus: any;
  requestedHop: any;
  clearRequestedHop: () => void;
  selectLatestHop: () => void;
  handleSelectHistoryEventId: (eventId: string | null, source?: "user" | "playback" | "sync") => void;
  loadHistory: (sessionId: string, cursor: string | null, isLoadMore: boolean) => void;
}

export function AuditFilesystemWorkspace(props: AuditFilesystemWorkspaceProps) {
  const [mobileTab, setMobileTab] = useState<"map" | "timeline">("map");

  return (
    <div className="flex flex-col h-full w-full">
      <div className="flex lg:hidden gap-2 border-b border-border pb-2 mb-4">
        <button
          onClick={() => setMobileTab("map")}
          className={`px-4 py-2 text-sm font-medium rounded-t-lg ${mobileTab === "map" ? "bg-surface border-b-2 border-primary text-primary" : "text-text-subtle"}`}
        >
          Map
        </button>
        <button
          onClick={() => setMobileTab("timeline")}
          className={`px-4 py-2 text-sm font-medium rounded-t-lg ${mobileTab === "timeline" ? "bg-surface border-b-2 border-primary text-primary" : "text-text-subtle"}`}
        >
          Timeline
        </button>
      </div>
      <div
        className={
          props.isFullscreen
            ? "min-h-0 flex-1 flex overflow-hidden"
            : "flex flex-col lg:flex-row items-stretch min-h-[calc(100dvh-12rem)] lg:flex-1"
        }
      >
        <div
          className={
            props.isFullscreen
              ? `min-w-0 flex-1 h-full ${mobileTab === "map" ? "flex" : "hidden"} lg:flex flex-col`
              : `min-w-0 flex-1 h-full ${mobileTab === "map" ? "flex" : "hidden"} lg:flex flex-col`
          }
        >
          <AuditNoticeRegion
            expiredSessionId={props.expiredSessionId}
            allSessions={props.allSessions}
            setExpiredSessionId={props.setExpiredSessionId}
            handleUserSelectSession={props.handleUserSelectSession}
            switchViewMode={props.switchViewMode}
            hasActiveFilters={props.hasActiveFilters}
            isSelectedFilteredOut={props.isSelectedFilteredOut}
            filteredSessionsCount={props.filteredSessionsCount}
            totalSessionsCount={props.totalSessionsCount}
            targetPathFilter={props.targetPathFilter}
            hideHomeOnly={props.hideHomeOnly}
            selectedSession={props.selectedSession}
            filteredActiveSessions={props.filteredActiveSessions}
            filteredClosedSessions={props.filteredClosedSessions}
            handleResetAuditFilters={props.handleResetAuditFilters}
            handleClearSelection={props.handleClearSelection}
          />
          {!props.isFullscreen && (
            <div className="mb-4">
              <AuditScopeBar
                filteredActiveSessions={props.filteredActiveSessions}
                filteredClosedSessions={props.filteredClosedSessions}
                selectedSessionId={props.selectedSessionId}
                handleUserSelectSession={props.handleUserSelectSession}
                totalSessionsCount={props.totalSessionsCount}
                hideHomeOnly={props.hideHomeOnly}
                targetPathFilter={props.targetPathFilter}
                handleResetAuditFilters={props.handleResetAuditFilters}
                allSessions={props.allSessions}
                directoryHasMore={props.directoryHasMore}
                directoryIsLoading={props.directoryIsLoading}
                directoryIsComplete={props.directoryIsComplete}
                loadMoreDirectory={props.loadMoreDirectory}
                auditSearchItems={props.auditSearchItems}
                auditSearchHasMore={props.auditSearchHasMore}
                auditSearchIsLoading={props.auditSearchIsLoading}
                auditSearchIsComplete={props.auditSearchIsComplete}
                searchAuditSessions={props.searchAuditSessions}
                loadMoreAuditSearch={props.loadMoreAuditSearch}
                clearAuditSearch={props.clearAuditSearch}
                auditStatus={props.auditStatus}
                auditErrorMessage={props.auditErrorMessage}
                retryInitialDirectory={props.retryInitialDirectory}
                handleToggleHideHomeOnly={props.handleToggleHideHomeOnly}
                handleSelectTargetPath={props.handleSelectTargetPath}
                distinctPaths={props.distinctPaths}
                homeOnlyCount={props.homeOnlyCount}
                filteredSessionsCount={props.filteredSessionsCount}
                selectedPath={props.selectedPath}
              />
            </div>
          )}
          <TopologyCanvas
          snapshot={props.auditSnapshot ?? props.snapshot}
          regionStatus={props.regionStatus}
          streamState={props.streamState}
          freshnessState={props.freshnessState}
          selectedSessionId={props.selectedSessionId}
          selectedPath={props.selectedPath}
          activeHop={props.activeHop}
          hopDurationMs={props.playbackSpeed}
          title={props.auditCanvasTitle}
          subtitle={props.auditCanvasSubtitle}
          onSelectSession={props.handleUserSelectSession}
          onSelectPath={props.selectPath}
          isExpanded={props.isFullscreen}
          onToggleExpand={props.onToggleFullscreen}
          onRefresh={props.refresh}
          onReconnect={props.handleReconnect}
          staleThresholdMs={DEFAULT_STALE_THRESHOLD_MS}
          isAuditMode={true}
          isResizingContainer={props.isDraggingTimeline}
          className="h-full flex-1 min-h-0"
        />
      </div>

      {!props.isTimelineCollapsed && (
        <TimelineSplitter
          isDragging={props.isDraggingTimeline}
          width={props.timelineWidth}
          onMouseDown={props.handleSplitterMouseDown}
          onDoubleClick={props.handleResetTimelineWidth}
          onKeyDown={props.handleSplitterKeyDown}
          className={props.isFullscreen ? "hidden sm:flex" : "hidden lg:flex"}
        />
      )}

      <div className={`${mobileTab === "timeline" ? "flex" : "hidden"} lg:flex h-full`}>
        <FilesystemTimelinePanel
        collapsed={props.isTimelineCollapsed}
        isDragging={props.isDraggingTimeline}
        width={props.timelineWidth}
        variant={props.isFullscreen ? "fullscreen" : "page"}
        selectedSession={props.selectedSession}
        history={props.history}
        anchoredHop={props.anchoredHop}
        historyStatus={props.historyStatus}
        historyCursor={props.historyCursor}
        historyTotalItems={props.historyTotalItems}
        historyTotalSuccessfulItems={props.historyTotalSuccessfulItems}
        historyComplete={props.historyComplete}
        replay={props.replayPresentation}
        activeTab={props.activeForensicTab}
        onTabChange={props.setActiveForensicTab}
        responsePanel={props.responsePanel}
        hopResolutionStatus={props.hopResolutionStatus}
        requestedHop={props.requestedHop}
        onClearHop={props.clearRequestedHop}
        onShowLatestHop={props.selectLatestHop}
        onSelectHistoryEventId={props.handleSelectHistoryEventId}
        onLoadEarlier={() => {
          if (props.selectedSessionId) {
            void props.loadHistory(props.selectedSessionId, props.historyCursor, true);
          }
        }}
      />
      </div>
    </div>
    </div>
  );
}
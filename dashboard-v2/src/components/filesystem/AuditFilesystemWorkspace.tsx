/* eslint-disable @typescript-eslint/no-explicit-any */
import React from "react";
import { AuditNoticeRegion } from "./AuditNoticeRegion";
import { TopologyCanvas } from "./TopologyCanvas";
import { TimelineSplitter } from "./TimelineSplitter";
import { FilesystemTimelinePanel } from "./FilesystemTimelinePanel";
import { DEFAULT_STALE_THRESHOLD_MS } from "./filesystemUtils";
import type { FilesystemClosedSession, FilesystemTopologySession, FilesystemTopologySnapshot } from "@/lib/dashboardTypes";
import type { ForensicTab } from "./FilesystemActivity";

export interface AuditFilesystemWorkspaceProps {
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
  return (
    <div
      className={
        props.isFullscreen
          ? "min-h-0 flex-1 flex overflow-hidden"
          : "flex flex-col lg:flex-row items-stretch lg:h-[600px] xl:h-[660px]"
      }
    >
      <div
        className={
          props.isFullscreen
            ? "min-w-0 flex-1 h-full flex flex-col"
            : "min-w-0 flex-1 h-full flex flex-col min-h-[480px] lg:min-h-0"
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
  );
}

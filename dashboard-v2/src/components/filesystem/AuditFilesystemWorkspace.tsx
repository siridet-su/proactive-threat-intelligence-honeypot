import React, { useState } from "react";
import { AuditNoticeRegion } from "./AuditNoticeRegion";
import { TopologyCanvas, deriveTopologyPresentationContext } from "./TopologyCanvas";
import { TimelineSplitter } from "./TimelineSplitter";
import { FilesystemTimelinePanel } from "./FilesystemTimelinePanel";
import { DEFAULT_STALE_THRESHOLD_MS } from "./filesystemUtils";

import { useFilesystemContext } from "./FilesystemContext";

export interface AuditFilesystemWorkspaceProps {
  isFullscreen: boolean;
  onToggleFullscreen: () => void;
}

export function AuditFilesystemWorkspace({ isFullscreen, onToggleFullscreen }: AuditFilesystemWorkspaceProps) {
  const props = useFilesystemContext();

  const [mobileTab, setMobileTab] = useState<"map" | "timeline">("map");

  return (
    <div className="relative z-10 flex flex-col h-full w-full">
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
          isFullscreen
            ? "min-h-0 flex-1 flex overflow-hidden"
            : "flex flex-col lg:flex-row items-stretch h-[calc(100dvh-12.5rem)] min-h-[600px] overflow-hidden rounded-b-xl"
        }
      >
        <div
          className={
            isFullscreen
              ? `min-w-0 flex-1 ${mobileTab === "map" ? "flex" : "hidden"} lg:flex flex-col`
              : `min-w-0 flex-1 ${mobileTab === "map" ? "flex" : "hidden"} lg:flex flex-col`
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
            retainedMatchingCount={props.retainedMatchingCount}
            retainedLoadedCount={props.retainedLoadedCount}
            retainedTotalCount={props.retainedTotalCount}
            retainedCountStatus={props.retainedCountStatus}
          />
          <TopologyCanvas
            snapshot={props.auditSnapshot ?? props.snapshot}
            regionStatus={props.regionStatus}
            streamState={props.streamState}
          freshnessState={props.freshnessState}
          selectedSessionId={props.selectedSessionId}
          selectedPath={props.selectedPath}
          activeHop={props.activeHop}
          displayedTransitions={props.displayedTransitions}
          currentTransition={props.currentTransition}
          hopDurationMs={props.playbackSpeed}
          title={props.auditCanvasTitle}
          subtitle={props.auditCanvasSubtitle}
          onSelectSession={props.handleUserSelectSession}
          onSelectPath={props.selectPath}
          isExpanded={isFullscreen}
          onToggleExpand={onToggleFullscreen}
          onRefresh={props.refresh}
          onReconnect={props.handleReconnect}
          staleThresholdMs={DEFAULT_STALE_THRESHOLD_MS}
          presentationContext={deriveTopologyPresentationContext("audit", props.selectedSession)}
          isResizingContainer={props.isDraggingTimeline}
          className="flex-1 min-h-0"
        />
      </div>

      {!props.isTimelineCollapsed && (
        <TimelineSplitter
          isDragging={props.isDraggingTimeline}
          width={props.timelineWidth}
          onPointerDown={props.handleSplitterPointerDown}
          onPointerMove={props.handleSplitterPointerMove}
          onPointerUp={props.handleSplitterPointerUp}
          onPointerCancel={props.handleSplitterPointerCancel}
          onDoubleClick={props.handleResetTimelineWidth}
          onKeyDown={props.handleSplitterKeyDown}
          className={isFullscreen ? "hidden sm:flex" : "hidden lg:flex"}
        />
      )}

      <div className={`${mobileTab === "timeline" ? "flex" : "hidden"} lg:flex`}>
        <FilesystemTimelinePanel
        collapsed={props.isTimelineCollapsed}
        isDragging={props.isDraggingTimeline}
        width={props.timelineWidth}
        variant={isFullscreen ? "fullscreen" : "page"}
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

import re

with open('./dashboard-v2/src/components/filesystem/CwdRouteHistory.tsx', 'r') as f:
    content = f.read()

# Add imports
imports = """import { ReplayTransport } from "./ReplayTransport";
import { RouteEventList } from "./RouteEventList";
"""
content = content.replace('import { RegionState, type RegionStatus } from "@/components/ui/RegionState";', imports + 'import { RegionState, type RegionStatus } from "@/components/ui/RegionState";')

# Define the block replacement
replacement = """<ReplayTransport
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
                      />"""

start_re = re.search(r'\s*\{/\* Sleek Compact Hop Deck \*/\}', content)
end_re = re.search(r'\s*</ol>\n\s*</div>\n', content)

if start_re and end_re:
    new_content = content[:start_re.start()] + "\n                      " + replacement + "\n" + content[end_re.end():]

    # Let's fix the imports safely
    new_content = new_content.replace(
        """import {
  AlertCircle,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Clock,
  CornerDownRight,
  FastForward,
  History,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Rewind,
  Shield,
  Terminal,
} from "lucide-react";""",
        """import {
  History,
  Shield,
  Terminal,
} from "lucide-react";"""
    )

    new_content = new_content.replace(
        """import {
  actionLabel,
  formatFromPath,
  formatTimestamp,
  isReplayTimelineKeyboardKey,
  isInitialSshEntry,
  mapReplayTimelineKeyToIndex,
  mapReplayTimelineValueToIndex,
  statusLabel,
} from "./filesystemUtils";""",
        """import {
  formatTimestamp,
  isReplayTimelineKeyboardKey,
  mapReplayTimelineKeyToIndex,
} from "./filesystemUtils";"""
    )

    with open('./dashboard-v2/src/components/filesystem/CwdRouteHistory.tsx', 'w') as f:
        f.write(new_content)
    print("Patched successfully")
else:
    print("Could not find markers")

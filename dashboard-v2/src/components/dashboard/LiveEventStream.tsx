import Link from "next/link";
import { useState } from "react";
import { Pause, Play, Terminal } from "lucide-react";

import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { SeverityBadge } from "./SeverityBadge";
import { RegionState, type RegionStatus } from "@/components/ui/RegionState";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";

export function LiveEventStream() {
  const { threats, status, lastUpdated } = useThreatFeed();
  const [paused, setPaused] = useState(false);
  const [pausedEvents, setPausedEvents] = useState<DashboardThreatEvent[]>([]);
  const loading = status === "loading";
  const fetchFailed = status === "error";
  const events = (paused ? pausedEvents : threats).slice(0, 50);
  const feedState = liveFeedPresentation(status);
  const detail = paused
    ? `Snapshot paused · ${events.length} event${events.length === 1 ? "" : "s"}`
    : lastUpdated
      ? `${events.length} event${events.length === 1 ? "" : "s"} · updated ${new Date(lastUpdated).toLocaleTimeString([], { hour12: false })}`
      : "Waiting for the first event";

  const togglePause = () => {
    if (paused) {
      setPaused(false);
      setPausedEvents([]);
      return;
    }
    setPausedEvents(threats);
    setPaused(true);
  };

  return <div className="ui-panel flex h-full flex-col overflow-hidden">
    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-surface-subtle px-5 py-4">
      <div className="flex min-w-0 items-center gap-2">
        <Terminal className="h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold">Live event stream</h2>
            <span className={`ui-badge ${feedState.className}`}>{paused ? "Paused" : feedState.label}</span>
          </div>
          <p className="mt-0.5 truncate text-xs text-text-subtle" title={detail}>{detail}</p>
        </div>
      </div>
      <button type="button" onClick={togglePause} disabled={loading || fetchFailed} className="ui-button min-h-8 px-2.5 text-xs" aria-pressed={paused}>{paused ? <Play className="h-3.5 w-3.5" aria-hidden="true" /> : <Pause className="h-3.5 w-3.5" aria-hidden="true" />}{paused ? "Resume" : "Pause"}</button>
    </div>
    <div className="flex-1 space-y-2 overflow-y-auto p-3" aria-busy={loading} aria-live={paused ? "off" : "polite"}>
      {loading && Array.from({ length: 5 }, (_, index) => <div key={`loading-${index}`} className="flex gap-3 rounded-lg border border-border p-3" aria-hidden="true"><div className="ui-skeleton h-4 w-16" /><div className="min-w-0 flex-1 space-y-2"><div className="ui-skeleton h-4 w-2/3" /><div className="ui-skeleton h-3 w-full" /></div></div>)}
      {!loading && fetchFailed && <RegionState kind="error" title="Event stream unavailable" description="The latest session events could not be loaded." />}
      {!loading && !fetchFailed && events.map((event) => <Link key={event.id} href={`/threat-intel/${event.id}`} className="group flex flex-col gap-2 rounded-lg border border-transparent p-3 transition-colors duration-150 hover:border-border hover:bg-surface-hover focus-visible:border-primary-border sm:flex-row sm:items-start" aria-label={`Open details for ${event.sourceIp}`}><div className="w-20 shrink-0 font-mono text-xs text-text-subtle" suppressHydrationWarning>{new Date(event.timestamp).toLocaleTimeString([], { hour12: false })}</div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="font-medium text-info">[{event.sensor}]</span><span className="text-primary">{event.protocol ?? "unknown"}</span><span className="text-text-muted">from</span><span className="font-mono text-text">{event.sourceIp}</span></div><div className="mt-1 flex items-center gap-2"><span className="truncate text-text-muted" title={event.payloadPreview ?? undefined}><span className="mr-2 text-text-subtle">&gt;</span>{event.payloadPreview ?? "—"}</span></div></div><div className="mt-1 shrink-0 sm:mt-0"><SeverityBadge severity={event.severity} className="px-2 py-0 text-xs" /></div></Link>)}
      {!loading && !fetchFailed && events.length === 0 && <RegionState kind="empty" title={paused ? "No events in this snapshot" : "No recent events"} description={paused ? "Resume the stream to view incoming events." : "No events were returned in the last successful response."} />}
    </div>
  </div>;
}

function liveFeedPresentation(status: RegionStatus) {
  if (status === "error") return { label: "Unavailable", className: "border-danger-border bg-danger-subtle text-danger" };
  if (status === "stale") return { label: "Stale", className: "border-warning-border bg-warning-subtle text-warning" };
  if (status === "refreshing") return { label: "Updating", className: "border-info-border bg-info-subtle text-info" };
  if (status === "loading") return { label: "Connecting", className: "border-info-border bg-info-subtle text-info" };
  return { label: "Live", className: "border-success-border bg-success-subtle text-success" };
}

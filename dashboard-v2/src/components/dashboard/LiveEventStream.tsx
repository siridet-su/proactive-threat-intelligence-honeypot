import { useThreatFeed } from '@/components/threat/ThreatFeedProvider';
import { SeverityBadge } from './SeverityBadge';
import { Terminal } from 'lucide-react';
import { RegionState } from '@/components/ui/RegionState';

export function LiveEventStream() {
  const { threats, status } = useThreatFeed();
  const events = threats.slice(0, 50);
  const loading = status === "loading";
  const fetchFailed = status === "error";
  return (
    <div className="ui-panel flex h-full flex-col overflow-hidden">
      <div className="flex items-center gap-2 border-b border-border bg-surface-subtle px-5 py-4">
        <Terminal className="h-4 w-4 text-primary" />
        <h2 className="text-base font-semibold">Live event stream</h2>
      </div>

      <div className="flex-1 space-y-2 overflow-y-auto p-3" aria-busy={loading}>
        {loading && Array.from({ length: 5 }, (_, index) => <div key={`loading-${index}`} className="flex gap-3 rounded-lg border border-border p-3" aria-hidden="true"><div className="ui-skeleton h-4 w-16" /><div className="min-w-0 flex-1 space-y-2"><div className="ui-skeleton h-4 w-2/3" /><div className="ui-skeleton h-3 w-full" /></div></div>)}
        {!loading && fetchFailed && <RegionState kind="error" title="Event stream unavailable" description="The latest session events could not be loaded." />}
        {!loading && !fetchFailed && events.map((event) => (
          <div key={event.id} className="group flex flex-col gap-2 rounded-lg border border-transparent p-3 transition-colors hover:border-border hover:bg-surface-hover sm:flex-row sm:items-start">
            <div className="w-20 shrink-0 font-mono text-xs text-text-subtle" suppressHydrationWarning>
              {new Date(event.timestamp).toLocaleTimeString([], { hour12: false })}
            </div>
            <div className="flex-1 flex flex-col gap-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-info">[{event.sensor}]</span><span className="text-primary">{event.protocol ?? "unknown"}</span><span className="text-text-muted">from</span><span className="font-mono text-text">{event.sourceIp}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="truncate text-text-muted"><span className="mr-2 text-text-subtle">&gt;</span>
                  {event.payloadPreview ?? "—"}
                </span>
              </div>
            </div>
            <div className="flex-shrink-0 mt-1 sm:mt-0">
               <SeverityBadge severity={event.severity} className="text-xs px-2 py-0" />
            </div>
          </div>
        ))}
        {!loading && !fetchFailed && events.length === 0 && (
          <RegionState kind="empty" title="No recent events" description="No events were returned in the last successful response." />
        )}
      </div>
    </div>
  );
}

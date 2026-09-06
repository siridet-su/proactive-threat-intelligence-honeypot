import { useState, useEffect } from 'react';
import { isDashboardThreatEvent } from '@/lib/dashboardTypes';
import type { DashboardThreatEvent } from '@/lib/dashboardTypes';
import { SeverityBadge } from './SeverityBadge';
import { Terminal } from 'lucide-react';

export function LiveEventStream() {
  const [events, setEvents] = useState<DashboardThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const res = await fetch("/api/threats");
        if (res.ok) {
          const data: unknown = await res.json();
          if (Array.isArray(data)) {
            setEvents(data.filter(isDashboardThreatEvent).slice(0, 50)); // Show latest 50 events
          }
        }
      } catch {
        // The containing region communicates unavailable data without causing a
        // development error overlay for a recoverable polling failure.
      } finally {
        setLoading(false);
      }
    };

    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);
  return (
    <div className="ui-panel flex h-full flex-col overflow-hidden">
      <div className="flex items-center gap-2 border-b border-border bg-surface-subtle px-5 py-4">
        <Terminal className="h-4 w-4 text-primary" />
        <h2 className="text-base font-semibold">Live event stream</h2>
      </div>

      <div className="flex-1 space-y-2 overflow-y-auto p-3">
        {loading && Array.from({ length: 5 }, (_, index) => <div key={`loading-${index}`} className="flex gap-3 rounded-lg border border-border p-3" aria-hidden="true"><div className="ui-skeleton h-4 w-16" /><div className="min-w-0 flex-1 space-y-2"><div className="ui-skeleton h-4 w-2/3" /><div className="ui-skeleton h-3 w-full" /></div></div>)}
        {!loading && events.map((event) => (
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
               <SeverityBadge severity={event.severity} className="text-[10px] px-2 py-0" />
            </div>
          </div>
        ))}
        {!loading && events.length === 0 && (
          <div className="py-8 text-center text-text-muted">No recent events</div>
        )}
      </div>
    </div>
  );
}

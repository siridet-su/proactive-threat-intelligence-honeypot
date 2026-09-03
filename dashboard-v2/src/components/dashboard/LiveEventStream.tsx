import { useState, useEffect } from 'react';
import { isDashboardThreatEvent } from '@/lib/dashboardTypes';
import type { DashboardThreatEvent } from '@/lib/dashboardTypes';
import { SeverityBadge } from './SeverityBadge';
import { Terminal } from 'lucide-react';

export function LiveEventStream() {
  const [events, setEvents] = useState<DashboardThreatEvent[]>([]);

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
      } catch (err) {
        console.error("Failed to fetch events:", err);
      }
    };
    
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);
  return (
    <div className="bg-[#0a0a0f] border border-slate-800 rounded-lg overflow-hidden font-mono text-sm h-full flex flex-col">
      <div className="flex items-center gap-2 px-3 py-2 bg-slate-900 border-b border-slate-800">
        <Terminal className="w-4 h-4 text-cyan-500" />
        <span className="text-slate-400 text-xs tracking-wider uppercase">Live Event Stream</span>
        <div className="ml-auto flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-slate-700"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-slate-700"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/80 shadow-[0_0_8px_rgba(239,68,68,0.6)] animate-pulse"></div>
        </div>
      </div>
      
      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {events.map((event) => (
          <div key={event.id} className="group flex flex-col sm:flex-row sm:items-start gap-2 hover:bg-slate-900/50 p-2 rounded transition-colors border border-transparent hover:border-slate-800/80">
            <div className="flex-shrink-0 text-slate-500 w-20" suppressHydrationWarning>
              {new Date(event.timestamp).toLocaleTimeString([], { hour12: false })}
            </div>
            <div className="flex-1 flex flex-col gap-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-cyan-400 font-bold">[{event.sensor}]</span>
                <span className="text-purple-400">{event.protocol ?? "unknown"}</span>
                <span className="text-slate-300">from</span>
                <span className="text-amber-400">{event.sourceIp}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-slate-400 group-hover:text-slate-300 transition-colors truncate">
                  <span className="text-slate-500 mr-2">&gt;</span>
                  {event.payloadPreview ?? "—"}
                </span>
              </div>
            </div>
            <div className="flex-shrink-0 mt-1 sm:mt-0">
               <SeverityBadge severity={event.severity} className="text-[10px] px-2 py-0" />
            </div>
          </div>
        ))}
        {events.length === 0 && (
          <div className="text-slate-500 text-center py-8">No recent events</div>
        )}
      </div>
    </div>
  );
}

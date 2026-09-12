import { useMemo, useState } from "react";
import { Search, X } from "lucide-react";

import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { SeverityBadge } from "./SeverityBadge";
import { RegionState } from "@/components/ui/RegionState";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";

type SourceSummary = {
  ip: string;
  country: string;
  city: string;
  latestTechnique: string;
  eventCount: number;
  severity: DashboardThreatEvent["severity"];
};

export function AttackerTable() {
  const { threats, status } = useThreatFeed();
  const [query, setQuery] = useState("");
  const loading = status === "loading";
  const fetchFailed = status === "error";

  const sources = useMemo(() => {
    const summaries = new Map<string, SourceSummary>();
    for (const threat of threats) {
      if (!threat.src_ip) continue;
      const existing = summaries.get(threat.src_ip);
      if (existing) {
        existing.eventCount += 1;
        if (threat.severity === "Critical" || (threat.severity === "High" && existing.severity !== "Critical")) existing.severity = threat.severity;
        continue;
      }
      summaries.set(threat.src_ip, {
        ip: threat.src_ip,
        country: threat.geo.country || "Unknown",
        city: threat.geo.city || "Unknown",
        latestTechnique: threat.event_type || threat.classification,
        eventCount: 1,
        severity: threat.severity,
      });
    }
    return Array.from(summaries.values()).sort((left, right) => right.eventCount - left.eventCount).slice(0, 50);
  }, [threats]);

  const filteredSources = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return sources;
    return sources.filter((source) => [source.ip, source.country, source.city, source.latestTechnique, source.severity]
      .some((value) => value.toLowerCase().includes(normalizedQuery)));
  }, [query, sources]);

  return <div className="flex h-full flex-col gap-4">
    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
      <div className="relative w-full sm:w-64"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" aria-hidden="true" /><input type="search" placeholder="Search IP or location…" value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search top source IPs" className="ui-field w-full pl-9 pr-8" />{query && <button type="button" onClick={() => setQuery("")} className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-text-subtle hover:text-text" aria-label="Clear source search"><X className="h-3.5 w-3.5" aria-hidden="true" /></button>}</div>
      <span className="text-xs text-text-muted">{filteredSources.length} source{filteredSources.length === 1 ? "" : "s"}</span>
    </div>
    <div className="flex-1 overflow-x-auto"><table className="ui-table min-w-[620px]"><thead><tr><th className="px-4 py-3 font-medium">Source IP</th><th className="px-4 py-3 font-medium">Location</th><th className="px-4 py-3 font-medium">Latest technique</th><th className="px-4 py-3 text-right font-medium">Events</th><th className="px-4 py-3 font-medium">Highest severity</th></tr></thead><tbody>
      {loading && Array.from({ length: 5 }, (_, index) => <tr key={`loading-${index}`} aria-hidden="true">{Array.from({ length: 5 }, (_, column) => <td key={column}><div className="ui-skeleton h-4 w-full" /></td>)}</tr>)}
      {!loading && fetchFailed && <tr><td colSpan={5} className="p-4"><RegionState kind="error" title="Source IPs unavailable" description="The live threat feed could not be loaded." /></td></tr>}
      {!loading && !fetchFailed && filteredSources.length === 0 && <tr><td colSpan={5} className="p-4"><RegionState kind="empty" title={query ? "No matching source IPs" : "No source IPs"} description={query ? "Try a different search term." : "No source IPs were returned in the current live feed."} /></td></tr>}
      {!loading && !fetchFailed && filteredSources.map((source) => <tr key={source.ip} className="text-text-muted"><td className="font-mono text-xs text-primary">{source.ip}</td><td className="px-4 py-3"><div className="flex flex-col"><span className="text-text">{source.country}</span><span className="text-xs text-text-subtle">{source.city}</span></div></td><td className="max-w-48 truncate text-text-muted" title={source.latestTechnique}>{source.latestTechnique}</td><td className="text-right font-medium text-text">{source.eventCount.toLocaleString()}</td><td className="px-4 py-3"><SeverityBadge severity={source.severity} /></td></tr>)}
    </tbody></table></div>
  </div>;
}

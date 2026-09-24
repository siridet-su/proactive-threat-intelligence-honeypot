import { useMemo, useState } from "react";
import { Activity, MapPin, Radio, Search, X } from "lucide-react";

import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { SeverityBadge } from "./SeverityBadge";
import { RegionState } from "@/components/ui/RegionState";
import { cn } from "@/lib/utils";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";

type SourceSummary = {
  ip: string;
  country: string;
  city: string;
  latestTechnique: string;
  eventCount: number;
  severity: DashboardThreatEvent["severity"];
  latestTimestamp: number;
};

function severityRank(severity: string) {
  return { Critical: 4, High: 3, Medium: 2, Low: 1 }[severity] ?? 0;
}

function feedPresentation(status: string) {
  if (status === "ready") return { label: "Live feed", className: "border-success-border bg-success-subtle text-success", Icon: Radio };
  if (status === "refreshing") return { label: "Refreshing", className: "border-info-border bg-info-subtle text-info", Icon: Activity };
  if (status === "stale") return { label: "Stale feed", className: "border-warning-border bg-warning-subtle text-warning", Icon: Activity };
  if (status === "error") return { label: "Unavailable", className: "border-danger-border bg-danger-subtle text-danger", Icon: Activity };
  return { label: "Connecting", className: "border-info-border bg-info-subtle text-info", Icon: Activity };
}

export function AttackerTable() {
  const { threats, status } = useThreatFeed();
  const [query, setQuery] = useState("");
  const loading = status === "loading";
  const fetchFailed = status === "error";
  const presentation = feedPresentation(status);
  const FeedIcon = presentation.Icon;

  const sources = useMemo(() => {
    const summaries = new Map<string, SourceSummary>();
    for (const threat of threats) {
      if (!threat.src_ip) continue;
      const eventTimestamp = new Date(threat.timestamp).getTime();
      const existing = summaries.get(threat.src_ip);
      if (existing) {
        existing.eventCount += 1;
        if (severityRank(threat.severity) > severityRank(existing.severity)) existing.severity = threat.severity;
        if (eventTimestamp >= existing.latestTimestamp) {
          existing.latestTimestamp = eventTimestamp;
          existing.latestTechnique = threat.event_type || threat.classification || "Unknown";
          existing.country = threat.geo.country || "Unknown";
          existing.city = threat.geo.city || "Unknown";
        }
        continue;
      }
      summaries.set(threat.src_ip, {
        ip: threat.src_ip,
        country: threat.geo.country || "Unknown",
        city: threat.geo.city || "Unknown",
        latestTechnique: threat.event_type || threat.classification || "Unknown",
        eventCount: 1,
        severity: threat.severity,
        latestTimestamp: Number.isFinite(eventTimestamp) ? eventTimestamp : 0,
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

  const maxEvents = sources[0]?.eventCount ?? 1;

  return (
      <section className="ui-panel flex min-h-[320px] flex-col overflow-hidden p-4 sm:p-5" aria-labelledby="source-activity-title">
      <div className="flex flex-col gap-3 border-b border-border pb-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-start gap-2.5">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary-subtle text-primary">
              <Activity className="h-4 w-4" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h2 id="source-activity-title" className="text-base font-semibold text-text">Source activity</h2>
                <span className={`ui-badge ${presentation.className}`} aria-live="polite">
                  <FeedIcon className={`h-3.5 w-3.5 ${status === "refreshing" ? "motion-safe:animate-spin" : ""}`} aria-hidden="true" />
                  {presentation.label}
                </span>
              </div>
              <p className="mt-1 text-xs text-text-muted">Ranked by events in the shared threat feed.</p>
            </div>
          </div>
          <span className="shrink-0 rounded-full bg-surface-subtle px-2 py-1 font-mono text-[10px] tabular-nums text-text-subtle">{sources.length} sources</span>
        </div>

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative min-w-0 flex-1 sm:max-w-[250px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" aria-hidden="true" />
            <input type="search" placeholder="Search source or location" value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search source activity" className="ui-field w-full min-h-9 pl-9 pr-8 text-xs" />
            {query && <button type="button" onClick={() => setQuery("")} className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-text-subtle hover:text-text" aria-label="Clear source search"><X className="h-3.5 w-3.5" aria-hidden="true" /></button>}
          </div>
          <span className="text-[11px] text-text-subtle" aria-live="polite">Showing {filteredSources.length} ranked source{filteredSources.length === 1 ? "" : "s"}</span>
        </div>
      </div>

      {/* Scanning Laser Bar when loading or refreshing */}
      <div className="h-0.5 w-full bg-border/40 overflow-hidden relative mt-1">
        {(loading || status === "refreshing") && (
          <div
            className="absolute inset-y-0 w-56 bg-gradient-to-r from-transparent via-primary to-transparent"
            style={{
              animation: "pti-laser-scan 1.6s cubic-bezier(0.4, 0, 0.2, 1) infinite",
            }}
          />
        )}
      </div>

      <div className="mt-2 max-h-[420px] min-h-0 flex-1 overflow-auto rounded-lg border border-border/70">
        <table className={cn("ui-table min-w-[500px] transition-opacity duration-200", status === "refreshing" && "opacity-50")}>
          <thead className="sticky top-0 z-10">
            <tr>
              <th className="w-10 px-3 py-2.5 text-center text-[10px] uppercase tracking-wider">#</th>
              <th className="px-3 py-2.5 text-[10px] uppercase tracking-wider">Source</th>
              <th className="w-36 px-3 py-2.5 text-[10px] uppercase tracking-wider">Activity</th>
              <th className="w-28 px-3 py-2.5 text-[10px] uppercase tracking-wider">Risk</th>
            </tr>
          </thead>
          <tbody aria-busy={loading || status === "refreshing"}>
            {loading && Array.from({ length: 6 }, (_, index) => (
              <tr key={`loading-${index}`} aria-hidden="true">
                <td className="px-3 py-3 text-center font-mono text-[11px] text-text-subtle/60">
                  {String(index + 1).padStart(2, "0")}
                </td>
                <td className="max-w-0 px-3 py-3">
                  <div className="min-w-0">
                    <span className="block font-mono text-xs font-medium text-primary/70 animate-pulse">
                      ---.---.---.---
                    </span>
                    <span className="mt-1 flex items-center gap-1 text-[11px] text-text-subtle/70">
                      <MapPin className="h-3 w-3 shrink-0 text-text-subtle/50" aria-hidden="true" />
                      Resolving location…
                    </span>
                    <span className="mt-1 block text-[10px] text-text-subtle/60">
                      Analyzing activity signatures…
                    </span>
                  </div>
                </td>
                <td className="px-3 py-3">
                  <div className="min-w-0">
                    <div className="h-1.5 overflow-hidden rounded-full bg-surface-hover">
                      <div className="h-full w-12 rounded-full bg-primary/30 animate-pulse" />
                    </div>
                    <span className="mt-1.5 block font-mono text-[11px] tabular-nums text-text-subtle/70">
                      -- events
                    </span>
                  </div>
                </td>
                <td className="px-3 py-3">
                  <span className="inline-flex items-center rounded-full border border-border bg-surface-subtle px-2 py-0.5 text-[10px] font-semibold text-text-subtle/70 animate-pulse">
                    Evaluating
                  </span>
                </td>
              </tr>
            ))}
            {!loading && fetchFailed && <tr><td colSpan={4} className="p-4"><RegionState kind="error" title="Source activity unavailable" description="The live threat feed could not be loaded." /></td></tr>}
            {!loading && !fetchFailed && filteredSources.length === 0 && <tr><td colSpan={4} className="p-4"><RegionState kind="empty" title={query ? "No matching sources" : "No source activity"} description={query ? "Try a different search term." : "No source IPs were returned in the current live feed."} /></td></tr>}
            {!loading && !fetchFailed && filteredSources.map((source, index) => {
              const activityPercent = Math.max(7, Math.round((source.eventCount / maxEvents) * 100));
              return (
                <tr key={source.ip}>
                  <td className="px-3 py-3 text-center font-mono text-[11px] text-text-subtle">{String(index + 1).padStart(2, "0")}</td>
                  <td className="max-w-0 px-3 py-3">
                    <div className="min-w-0">
                      <span className="block truncate font-mono text-xs font-medium text-primary" title={source.ip}>{source.ip}</span>
                      <span className="mt-1 flex min-w-0 items-center gap-1 truncate text-[11px] text-text-muted" title={`${source.country} · ${source.city}`}><MapPin className="h-3 w-3 shrink-0 text-text-subtle" aria-hidden="true" />{source.country} · {source.city}</span>
                      <span className="mt-1 block truncate text-[10px] text-text-subtle" title={source.latestTechnique}>{source.latestTechnique}</span>
                    </div>
                  </td>
                  <td className="px-3 py-3">
                    <div className="min-w-0">
                      <div className="h-1.5 overflow-hidden rounded-full bg-surface-hover" role="meter" aria-label={`${source.ip} activity`} aria-valuemin={0} aria-valuemax={maxEvents} aria-valuenow={source.eventCount}>
                        <span className="block h-full rounded-full bg-primary transition-[width] duration-500" style={{ width: `${activityPercent}%` }} />
                      </div>
                      <span className="mt-1.5 block font-mono text-[11px] tabular-nums text-text">{source.eventCount.toLocaleString()} event{source.eventCount === 1 ? "" : "s"}</span>
                    </div>
                  </td>
                  <td className="px-3 py-3"><SeverityBadge severity={source.severity} className="text-[10px]" /></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

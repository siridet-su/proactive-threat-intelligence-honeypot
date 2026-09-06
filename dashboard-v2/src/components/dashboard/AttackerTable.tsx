import { useState, useEffect, useMemo } from 'react';
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";
import type { AttackerSummary, DashboardThreatEvent } from "@/lib/dashboardTypes";
import { SeverityBadge } from './SeverityBadge';
import { Search } from 'lucide-react';
import { RegionState } from '@/components/ui/RegionState';

export function AttackerTable() {
  const [threats, setThreats] = useState<DashboardThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch("/api/threats");
        if (!res.ok) throw new Error("Attacker request failed");
        const data: unknown = await res.json();
        if (!Array.isArray(data)) throw new Error("Attacker response unavailable");
        setThreats(data.filter(isDashboardThreatEvent));
        setFetchFailed(false);
      } catch {
        setFetchFailed(true);
      } finally {
        setLoading(false);
      }
    };

    fetchThreats();
    const interval = setInterval(fetchThreats, 5000);
    return () => clearInterval(interval);
  }, []);

  const attackers = useMemo(() => {
    const map = new Map<string, AttackerSummary>();
    for (const t of threats) {
      if (!t.src_ip) continue;
      if (!map.has(t.src_ip)) {
        map.set(t.src_ip, {
          ip: t.src_ip,
          country: t.geo.country || 'Unknown',
          asn: t.geo.city || 'Unknown',
          mainTechnique: t.event_type || t.classification,
          attackCount: 1,
          riskScore: 50,
          status: t.severity
        });
      } else {
        const existing = map.get(t.src_ip);
        if (!existing) continue;
        existing.attackCount += 1;
        existing.riskScore = Math.min(100, existing.riskScore + 5);
        if (t.severity === 'Critical') existing.status = 'Critical';
        else if (t.severity === 'High' && existing.status !== 'Critical') existing.status = 'High';
      }
    }
    return Array.from(map.values()).sort((a, b) => b.attackCount - a.attackCount).slice(0, 50);
  }, [threats]);
  const filteredAttackers = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return attackers;
    return attackers.filter((attacker) => [attacker.ip, attacker.country, attacker.asn, attacker.mainTechnique, attacker.status]
      .some((value) => value.toLowerCase().includes(normalizedQuery)));
  }, [attackers, query]);
  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-subtle" />
          <input
            type="text"
            placeholder="Search IPs, ASNs..."
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            aria-label="Search top threat actors"
            className="ui-field w-64 pl-9"
          />
        </div>
      </div>

      <div className="flex-1 overflow-x-auto">
        <table className="ui-table min-w-[680px]">
          <thead>
            <tr>
              <th className="px-4 py-3 font-medium">Source IP</th>
              <th className="px-4 py-3 font-medium">Location</th>
              <th className="px-4 py-3 font-medium">Main Technique</th>
              <th className="px-4 py-3 font-medium text-right">Attacks</th>
              <th className="px-4 py-3 font-medium text-center">Score</th>
              <th className="px-4 py-3 font-medium">Risk</th>
            </tr>
          </thead>
          <tbody>
            {loading && Array.from({ length: 5 }, (_, index) => <tr key={`loading-${index}`} aria-hidden="true">{Array.from({ length: 6 }, (_, column) => <td key={column}><div className="ui-skeleton h-4 w-full" /></td>)}</tr>)}
            {!loading && fetchFailed && <tr><td colSpan={6} className="p-4"><RegionState kind="error" title="Threat actors unavailable" description="The latest session directory could not be loaded." /></td></tr>}
            {!loading && !fetchFailed && filteredAttackers.length === 0 && <tr><td colSpan={6} className="p-4"><RegionState kind="empty" title={query ? "No matching threat actors" : "No threat actors"} description={query ? "Try a different search term." : "No source IPs were returned in the last successful response."} /></td></tr>}
            {!loading && !fetchFailed && filteredAttackers.map((attacker, i) => (
            <tr key={i} className="group text-text-muted"><td className="font-mono text-xs text-primary">{attacker.ip}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-col">
                    <span className="text-text">{attacker.country}</span><span className="text-xs text-text-subtle">{attacker.asn}</span>
                  </div>
                </td>
                <td className="text-text-muted">{attacker.mainTechnique}</td><td className="text-right font-medium text-text">{attacker.attackCount.toLocaleString()}</td>
                <td className="px-4 py-3 text-center">
                    <span className={`font-semibold ${attacker.riskScore > 80 ? 'text-danger' : attacker.riskScore > 50 ? 'text-warning' : 'text-success'}`}>
                    {attacker.riskScore}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <SeverityBadge severity={attacker.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

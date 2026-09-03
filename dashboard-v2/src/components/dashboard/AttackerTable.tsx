import { useState, useEffect, useMemo } from 'react';
import { isDashboardThreatEvent } from '@/lib/dashboardTypes';
import type { AttackerSummary, DashboardThreatEvent } from '@/lib/dashboardTypes';
import { SeverityBadge } from './SeverityBadge';
import { Search } from 'lucide-react';

export function AttackerTable() {
  const [threats, setThreats] = useState<DashboardThreatEvent[]>([]);

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await fetch("/api/threats");
        if (res.ok) {
          const data: unknown = await res.json();
          if (Array.isArray(data)) {
            setThreats(data.filter(isDashboardThreatEvent));
          }
        }
      } catch (err) {
        console.error("Failed to fetch threats for table:", err);
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
          asn: t.abuseipdb?.isp || t.geo.city || 'Unknown',
          mainTechnique: t.event_type,
          attackCount: 1,
          riskScore: t.abuseipdb?.abuseConfidenceScore ?? Math.min(100, 50),
          status: t.severity
        });
      } else {
        const existing = map.get(t.src_ip);
        if (!existing) continue;
        existing.attackCount += 1;

        if (t.abuseipdb?.abuseConfidenceScore !== undefined) {
           existing.riskScore = Math.max(existing.riskScore, t.abuseipdb.abuseConfidenceScore);
           if (t.abuseipdb.isp) existing.asn = t.abuseipdb.isp;
        } else {
           existing.riskScore = Math.min(100, existing.riskScore + 5);
        }

        if (t.severity === 'Critical') existing.status = 'Critical';
        else if (t.severity === 'High' && existing.status !== 'Critical') existing.status = 'High';
      }
    }
    return Array.from(map.values()).sort((a, b) => b.attackCount - a.attackCount).slice(0, 50);
  }, [threats]);
  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center justify-between">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input 
            type="text" 
            placeholder="Search IPs, ASNs..." 
            className="bg-slate-900/50 border border-slate-700 text-sm rounded-md pl-9 pr-4 py-1.5 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 text-slate-300 w-64 transition-all"
          />
        </div>
      </div>
      
      <div className="flex-1 overflow-x-auto">
        <table className="w-full text-sm text-left">
          <thead className="text-xs text-slate-400 uppercase bg-slate-800/50 border-y border-slate-700/50">
            <tr>
              <th className="px-4 py-3 font-medium">Source IP</th>
              <th className="px-4 py-3 font-medium">Location</th>
              <th className="px-4 py-3 font-medium">Main Technique</th>
              <th className="px-4 py-3 font-medium text-right">Attacks</th>
              <th className="px-4 py-3 font-medium text-center">Score</th>
              <th className="px-4 py-3 font-medium">Risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {attackers.map((attacker, i) => (
              <tr key={i} className="hover:bg-slate-800/30 transition-colors group">
                <td className="px-4 py-3 font-mono text-cyan-400 group-hover:text-cyan-300">{attacker.ip}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-col">
                    <span className="text-slate-300">{attacker.country}</span>
                    <span className="text-xs text-slate-500">{attacker.asn}</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-slate-400">{attacker.mainTechnique}</td>
                <td className="px-4 py-3 text-right font-medium text-slate-300">{attacker.attackCount.toLocaleString()}</td>
                <td className="px-4 py-3 text-center">
                  <span className={`font-bold ${attacker.riskScore > 80 ? 'text-red-400' : attacker.riskScore > 50 ? 'text-orange-400' : 'text-emerald-400'}`}>
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

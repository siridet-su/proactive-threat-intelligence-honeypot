import { AttackerInfo } from '@/types/honeypot';
import { SeverityBadge } from './SeverityBadge';
import { Search } from 'lucide-react';

interface AttackerTableProps {
  attackers: AttackerInfo[];
}

export function AttackerTable({ attackers }: AttackerTableProps) {
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

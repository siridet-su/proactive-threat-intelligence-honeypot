import { AttackerInfo } from '@/types/honeypot';
import { SeverityBadge } from './SeverityBadge';

interface ThreatMapProps {
  attackers: AttackerInfo[];
}

export function ThreatMap({ attackers }: ThreatMapProps) {
  // A simple CSS/SVG based world map visualization using mock markers
  return (
    <div className="flex flex-col lg:flex-row h-full gap-4">
      {/* Map visual area */}
      <div className="flex-1 relative bg-[#0a1128] rounded-xl border border-slate-800 overflow-hidden min-h-[300px]">
        {/* Background grid */}
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCI+CjxwYXRoIGQ9Ik0wIDBoNDB2NDBIMHoiIGZpbGw9Im5vbmUiLz4KPHBhdGggZD0iTTAgNDBoNDBWMCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMWUyOTNiIiBzdHJva2Utd2lkdGg9IjEiIG9wYWNpdHk9IjAuNSIvPgo8L3N2Zz4=')] opacity-30"></div>
        
        {/* Map outline approximation (placeholder SVG for a real map) */}
        <div className="absolute inset-0 flex items-center justify-center p-4">
          <svg viewBox="0 0 1000 500" className="w-full h-full opacity-20 text-cyan-500" fill="currentColor">
            <path d="M150,100 Q200,80 300,120 T500,100 T700,150 T850,120 T900,200 T800,300 T600,400 T400,350 T200,400 T100,300 Z" />
            <path d="M100,200 Q150,180 200,250 T250,350 T150,400 T80,300 Z" />
            <path d="M600,150 Q700,100 800,180 T750,300 T650,280 T580,200 Z" />
          </svg>
        </div>

        {/* Attack markers */}
        {attackers.map((attacker, i) => {
          // Normalize lat/lng to percentage of container for simple positioning
          const x = ((attacker.longitude + 180) / 360) * 100;
          const y = ((90 - attacker.latitude) / 180) * 100;
          
          return (
            <div 
              key={i} 
              className="absolute w-4 h-4 -ml-2 -mt-2 rounded-full"
              style={{ left: `${x}%`, top: `${y}%` }}
            >
              <div className="absolute inset-0 bg-red-500 rounded-full animate-ping opacity-75"></div>
              <div className="absolute inset-1 bg-red-400 rounded-full shadow-[0_0_10px_rgba(248,113,113,0.8)]"></div>
            </div>
          );
        })}
        
        <div className="absolute bottom-4 left-4 flex gap-3 text-xs bg-slate-900/80 p-2 rounded-md border border-slate-800 backdrop-blur-sm">
          <div className="flex items-center gap-1.5">
             <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_5px_rgba(248,113,113,0.8)]"></div>
             <span className="text-slate-300">Active Threat</span>
          </div>
        </div>
      </div>
      
      {/* Side list */}
      <div className="w-full lg:w-64 flex flex-col gap-3">
        <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-1">Top Sources</h4>
        <div className="flex-1 overflow-y-auto pr-2 space-y-2">
          {attackers.slice(0, 5).map((attacker, i) => (
            <div key={i} className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50 flex flex-col gap-2 hover:bg-slate-800 transition-colors">
              <div className="flex justify-between items-start">
                <span className="text-sm font-medium text-slate-200">{attacker.country}</span>
                <SeverityBadge severity={attacker.status} />
              </div>
              <div className="flex justify-between items-end">
                <span className="text-xs text-slate-400 font-mono">{attacker.ip}</span>
                <span className="text-xs font-bold text-cyan-400">{attacker.attackCount.toLocaleString()}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

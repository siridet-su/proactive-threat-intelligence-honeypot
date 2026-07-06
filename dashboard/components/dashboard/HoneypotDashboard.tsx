'use client';

import { 
  ShieldAlert, Activity, Users, Globe, Server, Database, 
  Terminal, Filter, Clock, AlertTriangle,
  Wifi, Target, Fingerprint, Layers, Map as MapIcon, Key, FileTerminal
} from 'lucide-react';
import { 
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, 
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

import { 
  mockLiveEvents, mockAttackers, mockTimelineData, mockAttackTypes, mockServices, 
  mockUsernames, mockPasswords, mockBehavior, mockFingerprints, mockMitre, mockSensors 
} from '@/data/honeypotMockData';

import { MetricCard } from './MetricCard';
import { SectionCard } from './SectionCard';
import { SeverityBadge } from './SeverityBadge';
import { RiskGauge } from './RiskGauge';
import { ThreatMap } from './ThreatMap';
import { LiveEventStream } from './LiveEventStream';
import { AttackerTable } from './AttackerTable';
import { SensorHealthCard } from './SensorHealthCard';

const COLORS = ['#3b82f6', '#10b981', '#8b5cf6', '#f59e0b', '#ef4444', '#ec4899', '#06b6d4'];

export function HoneypotDashboard() {
  return (
    <div className="min-h-screen bg-[#020617] text-slate-300 font-sans selection:bg-cyan-900 selection:text-cyan-50">
      
      {/* 1. Header / Navigation */}
      <header className="sticky top-0 z-50 bg-[#020617]/80 backdrop-blur-md border-b border-slate-800/80 p-4">
        <div className="max-w-[1600px] mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-4">
            <div className="relative flex items-center justify-center w-12 h-12 bg-cyan-950 rounded-xl border border-cyan-800/50 overflow-hidden shadow-[0_0_15px_rgba(6,182,212,0.15)] group">
              <div className="absolute inset-0 bg-cyan-500/20 blur-xl group-hover:bg-cyan-500/30 transition-all"></div>
              <ShieldAlert className="w-7 h-7 text-cyan-400 relative z-10 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-black tracking-tight text-white flex items-center gap-2">
                HONEYPOT <span className="text-cyan-500">THREAT INTELLIGENCE</span>
              </h1>
              <p className="text-xs md:text-sm text-slate-400 max-w-xl">
                Real-time monitoring of attacker behavior, intrusion attempts, network fingerprints, and threat patterns.
              </p>
            </div>
          </div>
          
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-emerald-400 text-sm font-medium">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></div>
              Live Monitoring Active
            </div>
            <div className="hidden lg:flex items-center gap-2 text-xs text-slate-500 font-mono bg-slate-900 px-3 py-1.5 rounded-full border border-slate-800">
              <Clock className="w-3.5 h-3.5" />
              {new Date().toLocaleString()}
            </div>
            <div className="flex gap-2">
              <button className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-400 transition-colors" title="Time Range">
                <Clock className="w-4 h-4" />
              </button>
              <button className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-lg text-slate-400 transition-colors" title="Filter Settings">
                <Filter className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="p-4 max-w-[1600px] mx-auto space-y-6">
        
        {/* 2. Threat Overview KPI Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetricCard 
            title="Total Attack Events (24h)" 
            value="145,280" 
            icon={<Target className="w-6 h-6" />} 
            trend={12.5} 
            sparklineData={[45, 52, 38, 65, 89, 75, 120]}
            sparklineColor="#ef4444"
          />
          <MetricCard 
            title="Active Attacker Sessions" 
            value="432" 
            icon={<Terminal className="w-6 h-6" />} 
            trend={-5.2} 
            sparklineData={[30, 45, 55, 40, 35, 25, 20]}
            sparklineColor="#3b82f6"
          />
          <MetricCard 
            title="Unique Source IPs" 
            value="18,450" 
            icon={<Globe className="w-6 h-6" />} 
            trend={8.4} 
            sparklineData={[12, 15, 14, 18, 22, 25, 28]}
            sparklineColor="#8b5cf6"
          />
          <MetricCard 
            title="Critical Risk Events" 
            value="892" 
            icon={<AlertTriangle className="w-6 h-6" />} 
            trend={24.5} 
            sparklineData={[5, 8, 12, 10, 15, 25, 35]}
            sparklineColor="#ef4444"
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* 3. Attack Timeline */}
          <SectionCard title="Attack Event Timeline" icon={<Activity className="w-5 h-5" />} className="lg:col-span-2">
            <div className="h-[300px] w-full mt-4">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={mockTimelineData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorSsh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorHttp" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="time" stroke="#64748b" tick={{fill: '#64748b', fontSize: 12}} axisLine={false} tickLine={false} />
                  <YAxis stroke="#64748b" tick={{fill: '#64748b', fontSize: 12}} axisLine={false} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', color: '#f1f5f9', borderRadius: '8px' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Legend wrapperStyle={{ paddingTop: '20px' }} />
                  <Area type="monotone" dataKey="ssh" name="SSH" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorSsh)" />
                  <Area type="monotone" dataKey="http" name="HTTP/S" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#colorHttp)" />
                  <Area type="monotone" dataKey="portScan" name="Port Scan" stroke="#8b5cf6" strokeWidth={2} fill="transparent" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </SectionCard>

          {/* 4. Risk Scoring Panel */}
          <SectionCard title="Overall Network Risk Score" icon={<Target className="w-5 h-5" />}>
            <RiskGauge score={84} label="High" />
            <div className="mt-6 space-y-3">
              <h5 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Top Risk Factors</h5>
              <div className="space-y-2">
                <div className="flex justify-between items-center text-sm">
                  <span className="text-slate-300">Port Scanning Intensity</span>
                  <span className="text-red-400 font-mono">High</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-1.5"><div className="bg-red-500 h-1.5 rounded-full w-[85%]"></div></div>
                
                <div className="flex justify-between items-center text-sm pt-2">
                  <span className="text-slate-300">Brute-force Frequency</span>
                  <span className="text-orange-400 font-mono">Elevated</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-1.5"><div className="bg-orange-500 h-1.5 rounded-full w-[70%]"></div></div>
                
                <div className="flex justify-between items-center text-sm pt-2">
                  <span className="text-slate-300">Suspicious Commands</span>
                  <span className="text-red-400 font-mono">Critical</span>
                </div>
                <div className="w-full bg-slate-800 rounded-full h-1.5"><div className="bg-red-500 h-1.5 rounded-full w-[95%]"></div></div>
              </div>
            </div>
          </SectionCard>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* 5. Global Threat Map Panel */}
          <SectionCard title="Global Threat Origins" icon={<MapIcon className="w-5 h-5" />} className="lg:col-span-2">
             <ThreatMap attackers={mockAttackers} />
          </SectionCard>
          
          {/* 6. Attack Type Breakdown */}
          <SectionCard title="Attack Type Distribution" icon={<PieChart className="w-5 h-5" />}>
            <div className="h-[250px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={mockAttackTypes}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={5}
                    dataKey="value"
                    stroke="none"
                  >
                    {mockAttackTypes.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                    itemStyle={{ color: '#e2e8f0' }}
                  />
                  <Legend layout="vertical" verticalAlign="middle" align="right" />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </SectionCard>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
           {/* 7. Protocol & Service Monitoring */}
           <SectionCard title="Targeted Services" icon={<Server className="w-5 h-5" />}>
             <div className="h-[300px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={mockServices} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={true} vertical={false} />
                  <XAxis type="number" stroke="#64748b" tick={{fill: '#64748b', fontSize: 12}} />
                  <YAxis dataKey="name" type="category" stroke="#64748b" tick={{fill: '#cbd5e1', fontSize: 11}} />
                  <Tooltip 
                    cursor={{fill: '#1e293b', opacity: 0.4}}
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]}>
                    {mockServices.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
             </div>
           </SectionCard>

           {/* 8. Live Event Stream */}
           <SectionCard title="Real-time Event Stream" icon={<Wifi className="w-5 h-5" />} className="lg:col-span-2 overflow-hidden flex flex-col h-[400px]">
              <LiveEventStream events={mockLiveEvents} />
           </SectionCard>
        </div>

        {/* 9. Top Attacker IPs Table */}
        <SectionCard title="Top Identified Threat Actors" icon={<Users className="w-5 h-5" />}>
          <AttackerTable attackers={mockAttackers} />
        </SectionCard>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* 10. Credential Attack Analysis */}
          <SectionCard title="Credential Analysis (Brute Force)" icon={<Key className="w-5 h-5" />}>
            <div className="grid grid-cols-2 gap-6">
              <div>
                <h5 className="text-sm font-semibold text-slate-400 mb-3 border-b border-slate-800 pb-2">Top Usernames</h5>
                <div className="space-y-3">
                  {mockUsernames.slice(0, 5).map((u, i) => (
                    <div key={i} className="flex items-center justify-between">
                      <span className="font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded text-xs">{u.name}</span>
                      <span className="text-slate-400 text-sm">{u.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <h5 className="text-sm font-semibold text-slate-400 mb-3 border-b border-slate-800 pb-2">Top Passwords</h5>
                <div className="space-y-3">
                  {mockPasswords.slice(0, 5).map((p, i) => (
                    <div key={i} className="flex items-center justify-between">
                      <span className="font-mono text-orange-400 bg-orange-500/10 px-2 py-0.5 rounded text-xs">{p.name}</span>
                      <span className="text-slate-400 text-sm">{p.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </SectionCard>

          {/* 11. Attacker Behavior Analysis */}
          <SectionCard title="Observed Attacker Behavior" icon={<FileTerminal className="w-5 h-5" />}>
            <div className="flex flex-col sm:flex-row gap-6">
              <div className="flex-1 space-y-4">
                <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-xs uppercase tracking-wider mb-1">Avg Session Duration</div>
                  <div className="text-2xl font-bold text-slate-200">{mockBehavior.avgSessionDuration}</div>
                </div>
                <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-xs uppercase tracking-wider mb-1">Avg Cmds / Session</div>
                  <div className="text-2xl font-bold text-slate-200">{mockBehavior.commandsPerSession}</div>
                </div>
                <div className="bg-slate-900/50 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-xs uppercase tracking-wider mb-1">Malware Downloads</div>
                  <div className="text-2xl font-bold text-red-400">{mockBehavior.fileDownloads.toLocaleString()}</div>
                </div>
              </div>
              
              <div className="flex-[2]">
                <h5 className="text-sm font-semibold text-slate-400 mb-3 border-b border-slate-800 pb-2">Top Executed Commands</h5>
                <div className="space-y-2">
                  {mockBehavior.topCommands.map((cmd, i) => (
                    <div key={i} className="group flex items-center justify-between bg-slate-900/40 p-2 rounded border border-slate-800/50 hover:border-slate-700 transition-colors">
                      <span className="font-mono text-emerald-400 text-xs truncate max-w-[200px]">{cmd.command}</span>
                      <span className="text-slate-400 text-xs bg-slate-800 px-2 py-0.5 rounded">{cmd.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </SectionCard>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* 12. Network Fingerprint Intelligence */}
          <SectionCard title="Network Fingerprints" icon={<Fingerprint className="w-5 h-5" />}>
             <div className="space-y-3">
               {mockFingerprints.map((fp, i) => (
                 <div key={i} className="bg-slate-900/40 border border-slate-800 rounded-lg p-3">
                   <div className="flex justify-between items-start mb-2">
                     <span className="text-xs font-semibold text-slate-400 uppercase">{fp.type}</span>
                     <SeverityBadge severity={fp.risk} />
                   </div>
                   <div className="font-mono text-xs text-slate-300 break-all mb-2">{fp.value}</div>
                   <div className="text-xs text-slate-500 text-right">{fp.count.toLocaleString()} observations</div>
                 </div>
               ))}
             </div>
          </SectionCard>

          {/* 13. MITRE ATT&CK Mapping */}
          <SectionCard title="MITRE ATT&CK Mapping" icon={<Layers className="w-5 h-5" />} className="lg:col-span-2">
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              {mockMitre.map((mitre, i) => (
                <div key={i} className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-3 hover:bg-slate-800 transition-colors cursor-pointer group">
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-mono text-cyan-500 text-xs bg-cyan-500/10 px-1.5 py-0.5 rounded group-hover:bg-cyan-500/20">{mitre.id}</span>
                    <SeverityBadge severity={mitre.severity} className="text-[10px] px-1.5 py-0" />
                  </div>
                  <h5 className="font-medium text-slate-200 text-sm mt-2">{mitre.name}</h5>
                  <p className="text-xs text-slate-500 mt-1">{mitre.tactic}</p>
                  <div className="mt-3 text-right">
                    <span className="text-xs font-bold text-slate-400">{mitre.eventCount.toLocaleString()} events</span>
                  </div>
                </div>
              ))}
              {/* Add a few empty placeholder cards to show structure */}
              <div className="bg-slate-900/20 border border-slate-800 border-dashed rounded-lg p-3 flex items-center justify-center min-h-[100px]">
                <span className="text-slate-600 text-xs">No Recent Data</span>
              </div>
            </div>
          </SectionCard>
        </div>

        {/* 14. Sensor Health & Pipeline Status */}
        <SectionCard title="Infrastructure Health" icon={<Database className="w-5 h-5" />}>
           <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
             <SensorHealthCard sensors={mockSensors} />
           </div>
        </SectionCard>

      </main>
    </div>
  );
}

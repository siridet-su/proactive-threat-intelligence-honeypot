"use client";
import { Shield, Database, Network, Target, Plus, Edit2, Trash2, Users, Briefcase } from "lucide-react";

export default function PositionsPage() {
  const positions = [
    { id: "POS-01", title: "Lead Sentinel", status: "ACTIVE", icon: <Shield className="w-5 h-5 text-purple-400"/> },
    { id: "POS-02", title: "Data Guardian", status: "ACTIVE", icon: <Database className="w-5 h-5 text-blue-400"/> },
    { id: "POS-03", title: "Network Shield", status: "STANDBY", icon: <Network className="w-5 h-5 text-slate-400"/> },
    { id: "POS-04", title: "Threat Hunter", status: "ACTIVE", icon: <Target className="w-5 h-5 text-red-400"/> },
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-10">
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Job Positions</h1>
          <p className="text-slate-400 text-sm">Manage role-based access control and operative designations.</p>
        </div>
        <button className="flex items-center gap-2 px-6 py-3 bg-[#111116] border border-purple-500/50 hover:bg-purple-900/20 text-purple-300 rounded-lg transition-colors">
          <Plus className="w-4 h-4" /> Add Position
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 gap-4 mt-6 max-w-2xl">
        <div className="bg-[#111116] border border-slate-800/80 p-5 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-slate-800/50 rounded-lg text-slate-400"><Users className="w-6 h-6"/></div>
          <div>
            <div className="text-[10px] text-slate-500 font-mono tracking-widest">ACTIVE PERSONNEL</div>
            <div className="text-2xl font-bold text-white mt-1">24</div>
          </div>
        </div>
        <div className="bg-[#181111] border border-orange-900/30 p-5 rounded-xl flex items-center gap-4">
          <div className="p-3 bg-orange-900/20 rounded-lg text-orange-400"><Briefcase className="w-6 h-6"/></div>
          <div>
            <div className="text-[10px] text-slate-500 font-mono tracking-widest">TOTAL POSITIONS</div>
            <div className="text-2xl font-bold text-white mt-1">42</div>
          </div>
        </div>
      </div>

      {/* Table Section */}
      <div className="bg-[#111116] border border-slate-800/80 rounded-xl overflow-hidden mt-8">
        <div className="p-5 border-b border-slate-800/80 flex justify-between items-center">
          <h2 className="text-lg font-semibold text-white">Operational Roles</h2>
        </div>
        
        <table className="w-full text-left text-sm">
          <thead className="text-[10px] uppercase text-slate-500 font-mono border-b border-slate-800/50 bg-[#0a0a0c]">
            <tr>
              <th className="px-6 py-4">POSITION ID</th>
              <th className="px-6 py-4">POSITION TITLE</th>
              <th className="px-6 py-4">STATUS</th>
              <th className="px-6 py-4 text-right">ACTIONS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {positions.map((pos, i) => (
              <tr key={i} className="hover:bg-slate-800/20 text-slate-300 transition-colors">
                <td className="px-6 py-4 font-mono text-slate-400">{pos.id}</td>
                <td className="px-6 py-4 flex items-center gap-3 font-semibold text-slate-200">
                  <div className="w-8 h-8 rounded-lg bg-slate-800/50 flex items-center justify-center border border-slate-700/50">{pos.icon}</div>
                  {pos.title}
                </td>
                <td className="px-6 py-4">
                   <span className="bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-[10px] font-mono tracking-wider flex items-center gap-2 w-max">
                     <span className={`w-1.5 h-1.5 rounded-full ${pos.status === 'ACTIVE' ? 'bg-purple-500' : 'bg-slate-500'}`}></span>
                     {pos.status}
                   </span>
                </td>
                <td className="px-6 py-4 text-right flex justify-end gap-4">
                   <button className="text-slate-500 hover:text-white transition"><Edit2 className="w-4 h-4" /></button>
                   <button className="text-slate-500 hover:text-red-400 transition"><Trash2 className="w-4 h-4" /></button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
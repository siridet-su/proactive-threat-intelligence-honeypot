"use client";
import { Shield, Database, Network, Target, Plus, Edit2, Trash2, Users, Briefcase } from "lucide-react";

export default function PositionsPage() {
  const positions = [
    { id: "POS-01", title: "Lead Sentinel", status: "ACTIVE", icon: <Shield className="h-5 w-5 text-primary"/> },
    { id: "POS-02", title: "Data Guardian", status: "ACTIVE", icon: <Database className="h-5 w-5 text-info"/> },
    { id: "POS-03", title: "Network Shield", status: "STANDBY", icon: <Network className="h-5 w-5 text-neutral"/> },
    { id: "POS-04", title: "Threat Hunter", status: "ACTIVE", icon: <Target className="h-5 w-5 text-danger"/> },
  ];
  const activePositions = positions.filter((position) => position.status === "ACTIVE").length;

  return (
    <div className="space-y-7 pb-10">
      <header className="flex flex-col justify-between gap-4 border-b border-border pb-6 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Administration / Access</p>
          <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight">Job positions</h1>
          <p className="mt-2 text-sm text-text-muted">Review the role-based access designations used by operators.</p>
        </div>
        <button disabled title="Position creation is not available in this workspace" className="ui-button">
          <Plus className="h-4 w-4" aria-hidden="true" /> Add position
        </button>
      </header>

      {/* Stats Cards */}
      <div className="grid max-w-2xl grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="ui-panel flex items-center gap-4 p-5">
          <div className="rounded-lg border border-primary-border bg-primary-subtle p-3 text-primary"><Users className="h-6 w-6" aria-hidden="true"/></div>
          <div>
            <div className="text-xs font-medium text-text-muted">Active positions</div>
            <div className="mt-1 text-2xl font-semibold text-text">{activePositions}</div>
          </div>
        </div>
        <div className="ui-panel flex items-center gap-4 p-5">
          <div className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-warning"><Briefcase className="h-6 w-6" aria-hidden="true"/></div>
          <div>
            <div className="text-xs font-medium text-text-muted">Total positions</div>
            <div className="mt-1 text-2xl font-semibold text-text">{positions.length}</div>
          </div>
        </div>
      </div>

      {/* Table Section */}
      <div className="ui-panel overflow-hidden">
        <div className="flex items-center justify-between border-b border-border bg-surface px-5 py-4 sm:px-6">
          <div><h2 className="text-base font-semibold">Operational roles</h2><p className="mt-1 text-sm text-text-muted">Current position definitions and availability.</p></div>
        </div>

        <div className="ui-scroll-region">
        <table className="ui-table min-w-[680px]">
          <thead>
            <tr>
              <th scope="col">POSITION ID</th>
              <th scope="col">POSITION TITLE</th>
              <th scope="col">STATUS</th>
              <th scope="col" className="text-right">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {positions.map((pos, i) => (
              <tr key={i}>
                <td className="font-mono text-sm text-text">{pos.id}</td>
                <td>
                  <div className="flex items-center gap-3 font-semibold text-text">
                  <div className="grid h-8 w-8 place-items-center rounded-lg border border-border bg-surface-subtle">{pos.icon}</div>
                  {pos.title}
                  </div>
                </td>
                <td>
                   <span className={`ui-badge ${pos.status === "ACTIVE" ? "border-success-border bg-success-subtle text-success" : "border-neutral-border bg-neutral-subtle text-neutral"}`}>
                     <span className={`h-2 w-2 rounded-full ${pos.status === 'ACTIVE' ? 'bg-success' : 'bg-neutral'}`} aria-hidden="true"></span>
                     {pos.status}
                   </span>
                </td>
                <td className="text-right">
                   <div className="flex justify-end gap-2">
                   <button disabled title="Position editing is not available in this workspace" aria-label={`Edit ${pos.title}`} className="ui-button min-h-9 px-2"><Edit2 className="h-4 w-4" aria-hidden="true" /></button>
                   <button disabled title="Position deletion is not available in this workspace" aria-label={`Delete ${pos.title}`} className="ui-button min-h-9 px-2"><Trash2 className="h-4 w-4" aria-hidden="true" /></button>
                   </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </div>
    </div>
  );
}

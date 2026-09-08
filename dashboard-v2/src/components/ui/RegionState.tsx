import { AlertCircle, Inbox, RefreshCw } from "lucide-react";

export type RegionStatus = "loading" | "ready" | "refreshing" | "error" | "stale";

export function RefreshStatus({ status }: { status: RegionStatus }) {
  return <span role="status" className="inline-flex min-h-5 items-center gap-2 text-xs text-text-muted">
    {status === "refreshing" && <><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />Refreshing…</>}
    {status === "stale" && <><AlertCircle className="h-3.5 w-3.5 text-warning" aria-hidden="true" />Refresh failed · showing last successful result</>}
  </span>;
}

export function RegionState({ kind, title, description }: { kind: "loading" | "error" | "empty"; title: string; description?: string }) {
  const Icon = kind === "error" ? AlertCircle : Inbox;
  return (
    <div role={kind === "error" ? "alert" : "status"} aria-busy={kind === "loading"} className={`flex min-h-40 flex-col items-center justify-center gap-3 rounded-lg p-6 text-center ${kind === "error" ? "bg-danger-subtle" : "bg-surface-subtle"}`}>
      {kind === "loading" ? <div aria-hidden="true" className="w-full max-w-sm space-y-3"><div className="ui-skeleton h-3 w-2/3" /><div className="ui-skeleton h-3" /><div className="ui-skeleton h-3 w-4/5" /></div> : <Icon aria-hidden="true" className={`h-5 w-5 ${kind === "error" ? "text-danger" : "text-text-subtle"}`} />}
      <p className="font-medium text-text">{title}</p>
      {description && <p className="max-w-md text-sm text-text-muted">{description}</p>}
    </div>
  );
}

"use client";

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, ShieldAlert, Globe2 } from "lucide-react";
import type { WebHttpHint } from "@/lib/web-http-intel";

type HttpFeed = { items: WebHttpHint[]; coverage: string };

export default function HttpActivityPage() {
  const [feed, setFeed] = useState<HttpFeed | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const load = useCallback(async (signal?: AbortSignal) => {
    setStatus("loading");
    try {
      const response = await fetch("/api/http-activity", { cache: "no-store", signal });
      if (!response.ok) throw new Error("HTTP activity unavailable");
      const value: unknown = await response.json();
      if (!value || typeof value !== "object" || !Array.isArray((value as HttpFeed).items)) throw new Error("Invalid HTTP activity response");
      if (!signal?.aborted) { setFeed(value as HttpFeed); setStatus("ready"); }
    } catch {
      if (!signal?.aborted) setStatus("error");
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => void load(controller.signal), 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [load]);

  const items = feed?.items ?? [];
  const sqliCount = items.filter((item) => item.signals.includes("sqli")).length;
  const xssCount = items.filter((item) => item.signals.includes("xss")).length;

  return (
    <div className="space-y-5 pb-12">
      <header className="flex flex-wrap items-end justify-between gap-3 border-b border-border pb-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-widest text-primary">HTTP / Web-corp</p>
          <h1 className="mt-1 text-2xl font-bold text-text">HTTP activity</h1>
          <p className="mt-1 text-sm text-text-muted">Observed web login attempts and review-only injection hints.</p>
        </div>
        <button className="ui-button flex items-center gap-2 px-3 py-2 text-sm" type="button" onClick={() => void load()}>
          <RefreshCw className="h-4 w-4" aria-hidden="true" /> Refresh
        </button>
      </header>

      <div className="rounded-xl border border-warning-border bg-warning-subtle p-4 text-sm text-text">
        <div className="flex items-center gap-2 font-semibold"><ShieldAlert className="h-4 w-4" aria-hidden="true" /> Evidence boundary</div>
        <p className="mt-1">SQLi/XSS labels here are rule-based hints from submitted requests, not model predictions, confirmed exploitation, or trusted ATT&amp;CK findings. T1190 is a candidate for analyst review only. No credentials or submitted payloads are displayed.</p>
      </div>

      {status === "error" && <p role="alert" className="rounded-xl border border-warning-border p-4 text-sm">HTTP activity could not be loaded. The prior result, if any, may be stale.</p>}
      {status === "loading" && !feed && <p role="status" className="text-sm text-text-muted">Loading stored HTTP events…</p>}

      {feed && (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            {[["Stored attempts shown", items.length], ["SQLi hints", sqliCount], ["XSS hints", xssCount]].map(([label, value]) => (
              <div key={label} className="rounded-xl border border-border bg-surface p-4">
                <p className="text-xs uppercase tracking-wide text-text-muted">{label}</p>
                <p className="mt-1 text-2xl font-semibold text-text">{value}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-text-muted">{feed.coverage} Showing the latest 50 records; counts apply only to this page.</p>
          {items.length === 0 ? (
            <p className="rounded-xl border border-border bg-surface p-5 text-sm text-text-muted">No stored Web-corp login attempts are visible in this dashboard Mongo database.</p>
          ) : (
            <ol className="space-y-3" aria-label="Recent HTTP activity">
              {items.map((item) => (
                <li key={item.eventId} className="rounded-xl border border-border bg-surface p-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="flex items-center gap-2 font-semibold text-text"><Globe2 className="h-4 w-4 text-primary" aria-hidden="true" /> {item.method} web login · {item.sourceIp}</p>
                      <p className="mt-1 text-xs text-text-muted">{item.observedAt || "Time unavailable"} · outcome: {item.outcome}</p>
                    </div>
                    <span className="rounded-full border border-border px-2 py-1 text-xs text-text-muted">{item.signals.length ? "Review hint" : "No injection hint"}</span>
                  </div>
                  {item.signals.length > 0 && (
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                      {item.signals.map((signal) => <span key={signal} className="rounded-full border border-warning-border bg-warning-subtle px-2 py-1 font-semibold text-text">{signal === "sqli" ? "SQL injection pattern" : "XSS pattern"}</span>)}
                      <span className="text-text-muted">T1190 candidate · attempt only</span>
                    </div>
                  )}
                  {item.ruleIds.length > 0 && <p className="mt-2 text-xs text-text-muted">Rule hints: {item.ruleIds.join(", ")}</p>}
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </div>
  );
}

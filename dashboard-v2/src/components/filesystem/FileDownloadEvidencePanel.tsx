"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Clock3, Download, ExternalLink, RefreshCw } from "lucide-react";

import { RegionState } from "@/components/ui/RegionState";
import { formatTimestamp } from "./filesystemUtils";

const CANONICAL_SESSION_ID_PATTERN = /^session_v1_[0-9a-f]{32}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

interface DownloadEvent { event_id: string; timestamp: string | null; sha256: string | null; kind: "network_download" | "local_redirection" | "unverified" }
interface DownloadProjection { downloads: DownloadEvent[]; truncated: boolean }
type DownloadResult = { sessionId: string; projection?: DownloadProjection; error?: string };

function parseProjection(value: unknown, sessionId: string): DownloadProjection | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const data = value as Record<string, unknown>;
  if (data.ok !== true || data.schema_version !== "dashboard.session_file_downloads.v1"
    || data.requested_session_id !== sessionId || typeof data.session_id !== "string"
    || !CANONICAL_SESSION_ID_PATTERN.test(data.session_id) || typeof data.truncated !== "boolean"
    || !Array.isArray(data.downloads) || data.downloads.length > 100) return null;
  const seen = new Set<string>();
  const downloads: DownloadEvent[] = [];
  for (const item of data.downloads) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return null;
    const row = item as Record<string, unknown>;
    if (typeof row.event_id !== "string" || !row.event_id || row.event_id.length > 256 || seen.has(row.event_id)
      || (row.timestamp !== null && (typeof row.timestamp !== "string" || row.timestamp.length > 64))
      || (row.sha256 !== null && (typeof row.sha256 !== "string" || !SHA256_PATTERN.test(row.sha256)))
      || !["network_download", "local_redirection", "unverified"].includes(String(row.kind))) return null;
    seen.add(row.event_id);
    downloads.push({ event_id: row.event_id, timestamp: row.timestamp as string | null, sha256: row.sha256 as string | null, kind: row.kind as DownloadEvent["kind"] });
  }
  return { downloads, truncated: data.truncated };
}

export function FileDownloadEvidencePanel({ sessionId }: { sessionId: string }) {
  const [result, setResult] = useState<DownloadResult | null>(null);
  const [retry, setRetry] = useState(0);
  const current = result?.sessionId === sessionId ? result : null;

  useEffect(() => {
    const controller = new AbortController();
    void (async () => {
      try {
        const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/file-downloads`, {
          cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json" }, signal: controller.signal,
        });
        if (response.redirected || !response.ok) {
          setResult({ sessionId, error: response.status === 403 ? "Administrator access required." : "Download evidence is unavailable for this session." });
          return;
        }
        if (!(response.headers.get("content-type") ?? "").includes("application/json")) throw new Error("Invalid response");
        const projection = parseProjection(await response.json(), sessionId);
        if (!projection) throw new Error("Invalid response");
        setResult({ sessionId, projection });
      } catch {
        if (!controller.signal.aborted) setResult({ sessionId, error: "Download evidence could not be loaded." });
      }
    })();
    return () => controller.abort();
  }, [sessionId, retry]);

  return (
    <section className="rounded-xl border border-border bg-surface p-3" aria-label="Cowrie file artifact events" data-testid="file-download-evidence-panel">
      <div className="flex items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-1.5 font-semibold text-text"><Download className="h-3.5 w-3.5 text-primary" aria-hidden="true" />Cowrie file artifacts</div>
        <span className="font-mono text-text-subtle">{current?.projection ? `${current.projection.downloads.length} returned` : "Session scoped"}</span>
      </div>
      <p className="mt-2 text-xs leading-relaxed text-text-muted">Cowrie uses this event ID for both fetched files and local shell redirection. A hash identifies the captured artifact, not proof of a network transfer or execution.</p>
      {!current ? <div className="mt-3"><RegionState kind="loading" title="Loading file artifact events" /></div>
        : current.error ? <div className="mt-3 flex items-center gap-2 text-xs text-danger"><span role="alert">{current.error}</span><button type="button" className="ui-button" onClick={() => { setResult(null); setRetry((value) => value + 1); }}><RefreshCw className="h-3.5 w-3.5" />Retry</button></div>
          : current.projection?.downloads.length === 0 ? <div className="mt-3"><RegionState kind="empty" title="No file artifact events returned" description="No retained Cowrie file artifact event was found for this session." /></div>
            : <ol className="mt-3 space-y-2" aria-label="Session file artifacts">
              {current.projection?.truncated && <li className="rounded-lg border border-warning-border bg-warning-subtle p-2 text-xs text-warning">Showing the latest 100 events only.</li>}
              {current.projection?.downloads.map((item) => <li key={item.event_id} className="rounded-lg border border-border bg-surface-subtle p-2.5 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-semibold text-text">cowrie.session.file_download</span><time className="inline-flex items-center gap-1 font-mono text-text-subtle" dateTime={item.timestamp ?? undefined}><Clock3 className="h-3 w-3" />{formatTimestamp(item.timestamp)}</time></div>
                <div className="mt-1 text-text-muted">{item.kind === "network_download" ? "Network download recorded by Cowrie" : item.kind === "local_redirection" ? "Local shell redirection artifact — not a download" : "Artifact origin unverified — not counted as a network download"}</div>
                <div className="mt-1 break-all font-mono text-text-subtle">Event ID: {item.event_id}</div>
                {item.sha256 ? <Link className="mt-2 inline-flex max-w-full items-center gap-1 break-all font-mono text-primary hover:underline" href={`/malware-vault?q=${item.sha256}`}><span>SHA-256: {item.sha256}</span><ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" /></Link>
                  : <p className="mt-2 text-text-muted">No valid SHA-256 is retained for this event.</p>}
              </li>)}
            </ol>}
    </section>
  );
}

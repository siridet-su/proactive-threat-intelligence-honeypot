"use client";

import { use, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Activity, ArrowLeft, Fingerprint, Globe2, Printer, RefreshCw, ShieldAlert } from "lucide-react";
import type { WebHttpCapturedPayload, WebHttpHint } from "@/lib/web-http-intel";

type HttpDetail = { sessionId: string; items: WebHttpHint[]; payloads: WebHttpCapturedPayload[]; rawPayloadAccess: boolean; coverage: string };
type TiCache = { provider?: unknown; lookup_status?: unknown; normalized_context?: unknown; lookup_at?: unknown; expires_at?: unknown };
type TiResult = { ip: string | null; status: "loading" | "ready" | "none" | "error"; caches: TiCache[] };

function safeRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function eligiblePublicIp(ip: string): boolean {
  if (ip.includes(":")) {
    const value = ip.toLowerCase();
    return /^(2|3)[0-9a-f:]+$/.test(value) && !value.startsWith("2001:db8:") && !value.startsWith("2001:0db8:");
  }
  const parts = ip.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255 || (part.length > 1 && part.startsWith("0")))) return false;
  const [a, b] = parts.map(Number);
  return !(
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || (a === 192 && b === 0) ||
    (a === 192 && b === 88) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && parts[2] === "100") ||
    (a === 203 && b === 0 && parts[2] === "113")
  );
}

function formatTime(value: string): string {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : "Not recorded";
}

function signalName(value: "sqli" | "xss"): string { return value === "sqli" ? "SQL injection pattern" : "XSS pattern"; }

const RULE_EXPLANATIONS: Record<string, string> = {
  sqli_sql_comment: "SQL comment marker: may try to ignore the rest of a query.",
  sqli_union_select: "UNION SELECT syntax: may try to combine another query result.",
  sqli_boolean_tautology: "Boolean comparison: may try to change a query condition.",
  sqli_time_delay: "Time-delay function: may probe whether a database evaluates the input.",
  sqli_database_metadata: "Database catalog name: may probe schema information.",
  sqli_stacked_statement: "Statement separator followed by SQL: may try a second statement.",
  sqli_sql_keyword: "SQL-related keyword: weak pattern on its own; inspect the full field.",
  xss_script_tag: "Script tag: may try to make a browser run injected JavaScript.",
  xss_event_handler: "HTML event handler: may try to run code when an event fires.",
  xss_javascript_scheme: "JavaScript URL scheme: may try to execute code when a link is used.",
  xss_svg_script: "SVG load handler: may try to run code when SVG is rendered.",
};

export default function HttpSessionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [detail, setDetail] = useState<HttpDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error" | "missing">("loading");
  const [ti, setTi] = useState<TiResult>({ ip: null, status: "loading", caches: [] });
  const [asOf] = useState(() => Date.now());

  useEffect(() => {
    const controller = new AbortController();
    fetch(`/api/http-activity/session/${encodeURIComponent(id)}`, { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (response.status === 404) { setState("missing"); return; }
        if (!response.ok) throw new Error("detail unavailable");
        const value: unknown = await response.json();
        const data = safeRecord(value);
        if (data.sessionId !== id || !Array.isArray(data.items) || !Array.isArray(data.payloads) || typeof data.rawPayloadAccess !== "boolean") throw new Error("invalid detail");
        setDetail(data as HttpDetail);
        setState("ready");
      }).catch(() => { if (!controller.signal.aborted) setState("error"); });
    return () => controller.abort();
  }, [id]);

  const items = useMemo(() => detail?.items ?? [], [detail]);
  const capturedByEvent = useMemo(() => new Map((detail?.payloads ?? []).map((payload) => [payload.eventId, payload])), [detail]);
  const sources = useMemo(() => [...new Set(items.map((item) => item.sourceIp).filter((ip) => ip !== "unavailable"))], [items]);
  const sourceIp = sources.length === 1 ? sources[0] : null;
  useEffect(() => {
    if (!detail || !sourceIp || !eligiblePublicIp(sourceIp)) return;
    const controller = new AbortController();
    // Existing monitor projection reads stored, governed results only. It makes no provider call.
    const params = new URLSearchParams({ session_id: id, observable_type: "ip", observable_value: sourceIp });
    fetch(`/api/session-analysis/observable-ti?${params}`, { cache: "no-store", signal: controller.signal })
      .then(async (response) => {
        if (response.status === 404) { setTi({ ip: sourceIp, status: "none", caches: [] }); return; }
        if (!response.ok) throw new Error("TI unavailable");
        const value = safeRecord(await response.json());
        const observable = safeRecord(value.observable);
        if (observable.value !== sourceIp || observable.type !== "ip") throw new Error("TI identity mismatch");
        setTi({ ip: sourceIp, status: "ready", caches: Array.isArray(value.source_ip_cache) ? value.source_ip_cache.slice(0, 6) : [] });
      }).catch(() => { if (!controller.signal.aborted) setTi({ ip: sourceIp, status: "error", caches: [] }); });
    return () => controller.abort();
  }, [detail, id, sourceIp]);

  const hinted = items.filter((item) => item.signals.length > 0);
  const rejected = items.filter((item) => item.eventType === "web_login_attempt" && item.outcome === "rejected");
  const signals = [...new Set(items.flatMap((item) => item.signals))];
  const tiStatus = !sourceIp || !eligiblePublicIp(sourceIp) ? "ineligible" : ti.ip === sourceIp ? ti.status : "loading";

  return <main className="space-y-5 pb-12 print:p-0">
    <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border pb-4">
      <div>
        <Link href="/threat-intel" className="mb-3 inline-flex items-center gap-1 text-sm text-primary hover:underline"><ArrowLeft className="h-4 w-4" /> Threat Intel</Link>
        <p className="text-xs font-semibold uppercase tracking-widest text-primary">HTTP / Web-corp · session analysis</p>
        <h1 className="mt-1 text-2xl font-bold text-text">HTTP session {id.slice(0, 8)}…</h1>
        <p className="mt-1 break-all font-mono text-xs text-text-muted">{id}</p>
      </div>
      <button type="button" className="ui-button inline-flex items-center gap-2 px-3 py-2 text-sm print:hidden" onClick={() => window.print()}><Printer className="h-4 w-4" /> Print report</button>
    </header>

    {state === "loading" && <p role="status" className="rounded-xl border border-border p-5">Loading exact HTTP session…</p>}
    {state === "missing" && <p role="alert" className="rounded-xl border border-border p-5">No stored HTTP events match this exact sensor-issued session ID.</p>}
    {state === "error" && <p role="alert" className="rounded-xl border border-warning-border p-5">HTTP session detail could not be loaded. Try again later.</p>}
    {detail && <>
      <section className="rounded-xl border border-warning-border bg-warning-subtle p-4 text-sm text-text">
        <p className="flex items-center gap-2 font-semibold"><ShieldAlert className="h-4 w-4" /> Evidence boundary</p>
        <p className="mt-1">This ID links requests by browser cookie only, not verified attacker identity. SQLi/XSS are rule-based attempt hints; T1190 is a review candidate, not a confirmed exploit, model prediction, or trusted ATT&amp;CK finding. {detail.rawPayloadAccess ? "Captured query and login fields below are literal submitted data, including passwords. Handle printed or copied copies as sensitive research evidence." : "Literal request fields, including submitted passwords, are available to Admin operators only."}</p>
      </section>

      <section aria-label="HTTP session overview" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Requests captured" value={String(items.length)} />
        <Metric label="Injection hints" value={String(hinted.length)} />
        <Metric label="Rejected logins" value={String(rejected.length)} />
        <Metric label="Source IP" value={sourceIp ?? (sources.length > 1 ? "Multiple IPs" : "Not recorded")} />
      </section>

      <section className="rounded-xl border border-border bg-surface p-5">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-text"><Fingerprint className="h-5 w-5 text-primary" /> Session metadata</h2>
        <div className="mt-4 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <Metric label="Sensor" value="web-corp" />
          <Metric label="Source endpoint" value={`${sourceIp ?? "Not recorded"}:${items[0]?.sourcePort ?? "port not captured"}`} />
          <Metric label="Destination endpoint" value={`${items[0]?.destinationIp ?? "Not recorded"}:${items[0]?.destinationPort ?? "Not recorded"}`} />
          <Metric label="First request" value={formatTime(items[0]?.observedAt ?? "")} />
          <Metric label="Last request" value={formatTime(items.at(-1)?.observedAt ?? "")} />
          <Metric label="Session identity" value="Browser-cookie continuity" />
        </div>
        {sources.length > 1 && <p className="mt-3 text-sm text-warning">Multiple source IPs used this cookie. No source-IP attribution or ETI join is inferred.</p>}
      </section>

      <section className="rounded-xl border border-border bg-surface p-5">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-text"><Activity className="h-5 w-5 text-primary" /> Request chronology</h2>
        <p className="mt-1 text-sm text-text-muted">Observed method, path, response, literal captured request fields, and rule matches. A missing query in an older record cannot be reconstructed from its rule match.</p>
        <ol className="mt-4 max-h-[32rem] space-y-2 overflow-y-auto pr-1">
          {items.map((item, index) => <li key={item.eventId} className="rounded-lg border border-border bg-surface-subtle p-3 text-sm">
            <div className="flex flex-wrap items-start justify-between gap-2"><p className="font-semibold text-text">{index + 1}. {item.method} {item.path}</p><time className="text-xs text-text-muted">{formatTime(item.observedAt)}</time></div>
            <p className="mt-1 text-xs text-text-muted">{item.eventType === "web_login_attempt" ? `Login ${item.outcome}` : `HTTP ${item.statusCode ?? "status unavailable"}`} · {item.sourceIp}</p>
            {item.signals.length > 0 && <p className="mt-2 text-xs text-warning">{item.signals.map(signalName).join(" · ")} · T1190 review candidate only</p>}
            {item.matches.length > 0 && <p className="mt-1 text-xs text-text-muted">Matched: {item.matches.map((match) => `${match.field} / ${match.signal}_${match.ruleId}`).join(", ")}</p>}
            {detail.rawPayloadAccess ? <CapturedRequest payload={capturedByEvent.get(item.eventId)} matches={item.matches} /> : <p className="mt-2 text-xs text-text-muted">Literal payload fields require an Admin account.</p>}
          </li>)}
        </ol>
      </section>

      <section className="grid gap-4 lg:grid-cols-2" aria-label="HTTP observations and classification boundary">
        <div className="rounded-xl border border-border bg-surface p-5">
          <h2 className="text-lg font-semibold text-text">Observed access</h2>
          <div className="mt-3 grid gap-2 sm:grid-cols-2"><Metric label="Login attempts" value={String(items.filter((item) => item.eventType === "web_login_attempt").length)} /><Metric label="Rejected attempts" value={String(rejected.length)} /></div>
          <p className="mt-3 text-sm text-text-muted">Submitted login fields are available in the exact request chronology above. A rejected login does not establish account compromise.</p>
        </div>
        <div className="rounded-xl border border-border bg-surface p-5">
          <h2 className="text-lg font-semibold text-text">TTP review context</h2>
          <p className="mt-3 text-sm text-text">{hinted.length ? "T1190 — Exploit Public-Facing Application: candidate for analyst review" : "No HTTP TTP candidate from the stored rule hints"}</p>
          <p className="mt-2 text-sm text-text-muted">{hinted.length ? `${signals.map(signalName).join(" and ")} pattern(s) in ${hinted.length} request(s).` : "No matching injection rule was stored."} Neither Model1 nor Model2 classified these HTTP requests; the trusted finding count remains zero.</p>
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-xl border border-border bg-surface p-5">
          <h2 className="text-lg font-semibold text-text">Threat hypothesis</h2>
          <p className="mt-1 text-xs font-semibold uppercase tracking-wide text-warning">Contextual · not a validated finding</p>
          <p className="mt-3 text-sm text-text">{signals.length ? `The submitted requests match ${signals.map(signalName).join(" and ")} rules. This supports an investigation hypothesis of a web-application probing attempt, not successful exploitation.` : "No SQLi or XSS rule hint was observed in these stored requests. No injection hypothesis is established."}</p>
          <p className="mt-2 text-xs text-text-muted">Evidence: {hinted.length} matched request(s) of {items.length}. HTTP response codes and rejected login outcomes do not prove code execution, data access, or compromise.</p>
        </section>
        <section className="rounded-xl border border-border bg-surface p-5">
          <h2 className="text-lg font-semibold text-text">Response guidance</h2>
          <p className="mt-1 text-xs font-semibold uppercase tracking-wide text-warning">Manual review only · no automatic action</p>
          <p className="mt-3 text-sm text-text">{hinted.length ? "Review the web-server and application logs for this exact time window, source IP, path and rule IDs. Confirm server-side effects independently before labeling an exploit or taking action." : "Review this request sequence and authentication outcomes. There is no injection hint warranting a specific response from this session alone."}</p>
          <p className="mt-2 text-xs text-text-muted">If investigating a rejected login, compare authorized authentication logs; do not infer account compromise from a submitted username or password. Analyst approval is required for any containment.</p>
        </section>
      </div>

      <section className="rounded-xl border border-border bg-surface p-5">
        <h2 className="flex items-center gap-2 text-lg font-semibold text-text"><Globe2 className="h-5 w-5 text-primary" /> External threat intelligence</h2>
        <p className="mt-1 text-sm text-text-muted">Stored source-IP context only. Provider data is non-authoritative and does not establish who sent these HTTP requests.</p>
        {tiStatus === "loading" && <p className="mt-3 flex items-center gap-2 text-sm text-text-muted"><RefreshCw className="h-4 w-4 animate-spin" /> Checking existing IP evidence…</p>}
        {tiStatus === "ineligible" && <p className="mt-3 text-sm text-text-muted">No exact, single public source IP is available for an ETI lookup. Private/test IPs are ineligible.</p>}
        {tiStatus === "none" && <p className="mt-3 text-sm text-text-muted">No eligible stored TI sighting exists for this IP. HTTP events are not yet registered as ETI sightings; no provider call was made.</p>}
        {tiStatus === "error" && <p className="mt-3 text-sm text-warning">Stored TI context is currently unavailable; no reputation claim can be made.</p>}
        {tiStatus === "ready" && (ti.caches.length ? <ul className="mt-4 grid gap-3 sm:grid-cols-2">{ti.caches.map((entry, index) => {
          const context = safeRecord(entry.normalized_context);
          const expiry = typeof entry.expires_at === "string" ? Date.parse(entry.expires_at) : NaN;
          return <li key={`${String(entry.provider)}-${index}`} className="rounded-lg border border-border bg-surface-subtle p-3 text-sm">
            <p className="font-semibold text-text">{String(entry.provider ?? "Provider")}</p>
            <p className="mt-1 text-text-muted">Result: {String(entry.lookup_status ?? "not recorded")} · {Number.isFinite(expiry) && expiry < asOf ? "Expired" : "Stored context"}</p>
            {typeof context.abuse_confidence_score === "number" && <p>Provider abuse score: {context.abuse_confidence_score} (not model confidence)</p>}
            {typeof context.country_code === "string" && <p>Country code: {context.country_code}</p>}
            {typeof context.isp === "string" && <p>ISP: {context.isp}</p>}
            <p className="mt-1 text-xs text-text-muted">Retrieved: {typeof entry.lookup_at === "string" ? formatTime(entry.lookup_at) : "Not recorded"}</p>
          </li>;
        })}</ul> : <p className="mt-3 text-sm text-text-muted">The IP has a stored sighting but no governed provider result. No reputation claim is made.</p>)}
      </section>
      <p className="text-xs text-text-muted">{detail.coverage} This is a live read-side view, not an immutable forensic report. Print uses only the safe fields shown here.</p>
    </>}
  </main>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="min-w-0 rounded-lg border border-border bg-surface-subtle p-3"><p className="text-xs uppercase tracking-wide text-text-muted">{label}</p><p className="mt-1 break-words font-semibold text-text">{value}</p></div>;
}

function CapturedRequest({ payload, matches }: { payload?: WebHttpCapturedPayload; matches: WebHttpHint["matches"] }) {
  if (!payload) return <p className="mt-2 text-xs text-text-muted">No stored request fields for this event.</p>;
  const fields = payload.form ? Object.entries(payload.form) : [];
  return <div className="mt-3 rounded-lg border border-warning-border bg-surface p-3">
    <p className="text-xs font-semibold uppercase tracking-wide text-warning">Captured request payload · literal values</p>
    <p className="mt-1 text-xs text-text-muted">Matched fields: {matches.length ? matches.map((match) => `${match.field} (${match.signal}_${match.ruleId})`).join(" · ") : "No injection rule match"}</p>
    {matches.length > 0 && <ul className="mt-2 space-y-1 text-xs text-text">{matches.map((match) => <li key={`${match.field}.${match.signal}.${match.ruleId}`}><span className="font-semibold">{match.field}:</span> {RULE_EXPLANATIONS[`${match.signal}_${match.ruleId}`] ?? "Rule matched; inspect the captured field."}</li>)}</ul>}
    <dl className="mt-2 grid gap-2 sm:grid-cols-2">
      <CapturedField label="URL path (literal)" value={payload.rawPath} truncated={false} />
      <CapturedField label="URL query" value={payload.query} truncated={payload.truncatedFields.includes("http.query")} />
      {fields.map(([name, value]) => <CapturedField key={name} label={`Form: ${name}`} value={value} truncated={payload.truncatedFields.includes(`odoo_login.${name}`)} />)}
    </dl>
    {payload.form && <p className="mt-2 text-xs text-text-muted">Form values are the fields captured by the web-corp login sensor, not a raw multipart or JSON body. Submitted password is shown without masking.</p>}
  </div>;
}

function CapturedField({ label, value, truncated }: { label: string; value: string | null; truncated: boolean }) {
  return <div className="min-w-0 rounded border border-border p-2">
    <dt className="text-xs font-semibold text-text-muted">{label}{truncated ? " · truncated at capture" : ""}</dt>
    <dd className="mt-1 whitespace-pre-wrap break-all font-mono text-xs text-text">{value === null ? "Not stored or empty" : value === "" ? "(empty)" : value}</dd>
  </div>;
}

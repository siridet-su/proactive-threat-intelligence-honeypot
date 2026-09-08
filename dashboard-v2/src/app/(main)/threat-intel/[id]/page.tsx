"use client";

import { use, useMemo, useState } from "react";
import { AlertTriangle, Check, ChevronRight, Copy, MapPin, Printer, Terminal } from "lucide-react";
import Link from "next/link";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RegionState } from "@/components/ui/RegionState";
import { classificationBadgeClass, severityColor } from "@/lib/presentation";
import { cn } from "@/lib/utils";

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export default function SessionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const sessionId = resolvedParams.id;
  const { threats, status } = useThreatFeed();
  const threatData = useMemo(() => threats.find((threat) => threat.id === sessionId) ?? null, [sessionId, threats]);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const loading = status === "loading";
  const fetchFailed = status === "error";

  const handleCopyPayload = async (text: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
      }
      setCopiedPayload(true);
      window.setTimeout(() => setCopiedPayload(false), 2000);
    } catch {
      setCopiedPayload(false);
    }
  };

  if (loading) {
    return <div className="min-h-[500px] py-16"><RegionState kind="loading" title="Loading session analysis" description="Retrieving the latest evidence for this session." /></div>;
  }

  if (fetchFailed) {
    return <div className="min-h-[500px] py-16"><RegionState kind="error" title="Threat intelligence unavailable" description="This session could not be loaded because the session directory is currently unavailable." /></div>;
  }

  if (!threatData) {
    return <div className="min-h-[500px] py-16"><RegionState kind="empty" title="ERROR: SESSION ARCHIVED OR NOT FOUND" description="The session was not included in the latest successful directory response." /></div>;
  }

  const originIp = threatData.sourceIp || "Unknown";
  const country = threatData.geo.country || "Unknown";
  const city = threatData.geo.city || "Unknown";
  const lat = threatData.geo.lat || 0;
  const lon = threatData.geo.lon || 0;
  const severity = threatData.severity || "Unknown";
  const classification = threatData.classification || "Unknown";
  const markerColor = severityColor(severity);
  const abuseScore = threatData.abuseipdb?.abuseConfidenceScore;
  const isp = threatData.abuseipdb?.isp;
  const vtStats = threatData.virustotal?.attributes?.stats;

  return (
    <div className="space-y-7 pb-10">
      {/* Print only banner */}
      <div className="hidden border-b-2 border-border pb-4 print:block">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs font-bold uppercase tracking-widest text-primary">Proactive Threat Intelligence Honeypot</p>
            <h1 className="mt-1 text-xl font-bold text-text">Forensic Incident Investigation Report</h1>
          </div>
          <div className="text-right font-mono text-xs text-text-muted">
            <div>Session ID: {sessionId}</div>
            <div>Generated: {threatData.date} {threatData.time}</div>
          </div>
        </div>
      </div>

      <header className="flex flex-col gap-5 border-b border-border pb-6 print:hidden">
        <div className="flex flex-wrap items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-text-subtle">
          <Link href="/dashboard" className="text-primary hover:text-primary-action-hover">Session analysis</Link>
          <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
          <span className="font-mono text-text-subtle">{sessionId.substring(0, 12)}{sessionId.length > 12 ? "…" : ""}</span>
        </div>
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div>
            <h1 className="text-2xl font-semibold leading-8 tracking-tight sm:text-[28px] sm:leading-9">Session analysis</h1>
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <SeverityBadge severity={severity} />
              <span className="text-sm text-text-muted">Observed session</span>
              <span className="font-mono text-xs text-text-subtle">ID {sessionId}</span>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => window.print()}
              className="ui-button ui-button-primary min-h-9 px-3 text-xs sm:text-sm"
              title="Print forensic incident report or save as PDF"
              aria-label="Print or export session forensic report"
            >
              <Printer className="h-4 w-4" aria-hidden="true" />
              Print / Export report
            </button>
          </div>
        </div>
      </header>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:gap-6" aria-label="Session overview">
        <article className="ui-panel flex min-h-[390px] flex-col overflow-hidden xl:col-span-8">
          <div className="border-b border-border bg-surface px-5 py-4 sm:px-6">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
              <MapPin className="h-4 w-4" aria-hidden="true" />
              Session context
            </div>
            <h2 className="mt-1 text-base font-semibold sm:text-lg">Forensic target metadata</h2>
          </div>
          <div className="flex flex-1 flex-col p-5 sm:p-6">
            <dl className="grid gap-5 border-b border-border pb-5 sm:grid-cols-2 lg:grid-cols-3">
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Origin IP</dt>
                <dd className="mt-1 break-all font-mono text-base font-medium text-primary">{originIp}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Geo-location</dt>
                <dd className="mt-1 flex items-start gap-1.5 text-sm text-text">
                  <MapPin className="mt-0.5 h-3.5 w-3.5 shrink-0 text-text-subtle" aria-hidden="true" />
                  {city !== "Unknown" ? `${city}, ` : ""}{country}
                </dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Protocol</dt>
                <dd className="mt-1 font-mono text-sm text-text">{threatData.protocol ? threatData.protocol.toUpperCase() : "Unavailable"}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Capture sensor</dt>
                <dd className="mt-1 truncate font-mono text-sm text-text" title={threatData.sensor || undefined}>{threatData.sensor || "Unavailable"}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Session duration</dt>
                <dd className="mt-1 font-mono text-sm text-text">{threatData.duration || "Unavailable"}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Captured time</dt>
                <dd className="mt-1 font-mono text-sm text-text">{threatData.date} {threatData.time}</dd>
              </div>
            </dl>

            <div className="relative mt-5 min-h-[180px] flex-1 overflow-hidden rounded-lg border border-border bg-surface-subtle" aria-label="Session origin map">
              <ComposableMap
                projection="geoMercator"
                projectionConfig={{ scale: 420, center: [lon, lat] }}
                style={{ width: "100%", height: "100%" }}
              >
                <Geographies geography={geoUrl}>
                  {({ geographies }) => geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill="var(--map-land)"
                      stroke="var(--map-border)"
                      strokeWidth={0.5}
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "var(--map-hover)", outline: "none" },
                        pressed: { fill: "var(--map-hover)", outline: "none" },
                      }}
                    />
                  ))}
                </Geographies>
                {lat !== 0 && lon !== 0 && (
                  <Marker coordinates={[lon, lat]}>
                    <title>{`Origin location · ${city}, ${country}`}</title>
                    <circle r={6} fill={markerColor} stroke="var(--surface)" strokeWidth={2} />
                    <text textAnchor="middle" y={-16} fill="var(--text)" fontSize={14} fontWeight={600}>Origin</text>
                  </Marker>
                )}
              </ComposableMap>
              {lat === 0 || lon === 0 ? (
                <div className="absolute inset-0 grid place-items-center p-4">
                  <RegionState kind="empty" title="Location unavailable" description="This session does not include usable coordinates." />
                </div>
              ) : (
                <span className="pointer-events-none absolute bottom-3 left-3 rounded-md border border-border bg-surface px-2.5 py-1.5 font-mono text-xs text-text-subtle">Origin trace</span>
              )}
            </div>
          </div>
        </article>

        <article className="ui-panel flex min-h-[390px] flex-col p-5 sm:p-6 xl:col-span-4">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            Assessment
          </div>
          <h2 className="mt-1 text-base font-semibold sm:text-lg">Attacker profile</h2>
          <div className="mt-6 grid gap-4">
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Classification</p>
              <div className="mt-1.5 flex items-center gap-2">
                <span className={cn("ui-badge text-sm", classificationBadgeClass(classification, threatData.typeColor))}>{classification}</span>
              </div>
            </div>
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Criticality</p>
              <div className="mt-1.5"><SeverityBadge severity={severity} /></div>
            </div>
          </div>

          {abuseScore !== undefined ? (
            <div className="mt-6 rounded-lg border border-border bg-surface-subtle p-4 space-y-2.5">
              <div className="flex items-center justify-between text-xs font-semibold">
                <span className="text-text">AbuseIPDB Confidence</span>
                <span className={cn("font-mono", abuseScore > 50 ? "text-danger" : abuseScore > 20 ? "text-warning" : "text-success")}>
                  {abuseScore}%
                </span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-border">
                <div
                  className={cn("h-full transition-all duration-300", abuseScore > 50 ? "bg-danger" : abuseScore > 20 ? "bg-warning" : "bg-success")}
                  style={{ width: `${Math.min(100, Math.max(0, abuseScore))}%` }}
                />
              </div>
              {isp && (
                <p className="truncate text-xs text-text-muted">
                  <span className="font-medium text-text-subtle">ISP / Host:</span> {isp}
                </p>
              )}
            </div>
          ) : (
            <div className="mt-auto rounded-lg border border-border bg-surface-subtle p-4">
              <p className="text-sm font-semibold text-text">Analytical confidence</p>
              <p className="mt-1 text-xs text-text-muted">No external threat feed reputation score recorded for this host.</p>
            </div>
          )}
        </article>
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:gap-6" aria-label="Session evidence">
        <article className="ui-panel flex min-h-[320px] flex-col overflow-hidden xl:col-span-8">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border bg-surface px-5 py-4 sm:px-6">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
                <Terminal className="h-4 w-4" aria-hidden="true" />
                Evidence stream
              </div>
              <h2 className="mt-1 text-base font-semibold sm:text-lg">Live interaction shell</h2>
            </div>
            {threatData.payloadPreview ? (
              <div className="flex items-center gap-2">
                <span className="ui-badge border-success-border bg-success-subtle text-success text-xs">
                  Payload captured
                </span>
                <button
                  type="button"
                  onClick={() => void handleCopyPayload(threatData.payloadPreview!)}
                  className="ui-button min-h-8 px-2.5 text-xs"
                  title="Copy captured payload"
                  aria-label="Copy captured payload"
                >
                  {copiedPayload ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                  {copiedPayload ? "Copied" : "Copy payload"}
                </button>
              </div>
            ) : (
              <span className="ui-badge">No command stream</span>
            )}
          </div>
          {threatData.payloadPreview ? (
            <div className="flex flex-1 flex-col overflow-hidden bg-surface-subtle p-5 font-mono text-xs sm:p-6 sm:text-sm">
              <div className="flex select-none items-center gap-2 border-b border-border pb-3 text-xs text-text-subtle">
                <span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />
                <span>{threatData.sensor ? `Capture sensor · ${threatData.sensor}` : "Captured command evidence"}</span>
              </div>
              <pre className="mt-4 flex-1 overflow-x-auto whitespace-pre-wrap break-all font-mono leading-relaxed text-text selection:bg-primary-subtle selection:text-primary">
                <code>{threatData.payloadPreview}</code>
              </pre>
            </div>
          ) : (
            <div className="flex flex-1 items-center p-5 sm:p-6">
              <RegionState kind="empty" title="Interaction evidence unavailable" description="Command history is not included in the current session response." />
            </div>
          )}
        </article>

        <article className="ui-panel flex min-h-[320px] flex-col p-5 sm:p-6 xl:col-span-4">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            External intelligence
          </div>
          <h2 className="mt-1 text-base font-semibold sm:text-lg">Reputation analysis</h2>
          <div className="mt-5 flex flex-1 flex-col justify-center">
            {vtStats ? (
              <div className="rounded-lg border border-border bg-surface-subtle p-3.5 text-xs space-y-1.5">
                <div className="flex items-center justify-between font-medium text-text">
                  <span>VirusTotal Analysis</span>
                  <span className={cn("font-mono font-semibold", (vtStats.malicious ?? 0) > 0 ? "text-danger" : "text-success")}>
                    {vtStats.malicious ?? 0} malicious detections
                  </span>
                </div>
                {threatData.virustotal?.attributes?.meaningful_name && (
                  <p className="truncate text-text-muted font-mono">Sample: {threatData.virustotal.attributes.meaningful_name}</p>
                )}
              </div>
            ) : null}

            {!vtStats && <RegionState kind="empty" title="No external analysis recorded" description="This session does not include external reputation analysis." />}
          </div>
        </article>
      </section>
    </div>
  );
}

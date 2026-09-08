"use client";

import { use, useMemo } from "react";
import { AlertTriangle, ChevronRight, Download, FileText, MapPin, Terminal } from "lucide-react";
import Link from "next/link";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";

import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import { RegionState } from "@/components/ui/RegionState";
import { severityColor } from "@/lib/presentation";

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

export default function SessionDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const sessionId = resolvedParams.id;
  const { threats, status } = useThreatFeed();
  const threatData = useMemo(() => threats.find((threat) => threat.id === sessionId) ?? null, [sessionId, threats]);
  const loading = status === "loading";
  const fetchFailed = status === "error";

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

  return (
    <div className="space-y-7 pb-10">
      <header className="flex flex-col gap-5 border-b border-border pb-6">
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
            <span id="pdf-export-status" className="text-xs text-text-subtle">PDF export is not available in the current workspace.</span>
            <button type="button" disabled aria-describedby="pdf-export-status" className="ui-button" title="PDF export is not available">
              <FileText className="h-4 w-4" aria-hidden="true" />
              <Download className="h-3.5 w-3.5" aria-hidden="true" />
              Download session PDF
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
            <dl className="grid gap-5 border-b border-border pb-5 sm:grid-cols-3">
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Origin IP</dt>
                <dd className="mt-2 break-all font-mono text-base text-primary">{originIp}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Geo-location</dt>
                <dd className="mt-2 flex items-start gap-2 text-sm text-text">
                  <MapPin className="mt-0.5 h-4 w-4 shrink-0 text-text-subtle" aria-hidden="true" />
                  {city !== "Unknown" ? `${city}, ` : ""}{country}
                </dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Session duration</dt>
                <dd className="mt-2 font-mono text-base text-text">{threatData.duration || "Unavailable"}</dd>
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
          <div className="mt-7 grid gap-5">
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Classification</p>
              <p className="mt-2 break-words text-2xl font-semibold text-text">{classification}</p>
            </div>
            <div>
              <p className="text-xs font-medium uppercase tracking-[0.1em] text-text-subtle">Criticality</p>
              <div className="mt-2"><SeverityBadge severity={severity} /></div>
            </div>
          </div>
          <div className="mt-auto rounded-lg border border-border bg-surface-subtle p-4">
            <p className="text-sm font-semibold text-text">Analytical confidence</p>
            <p className="mt-1 text-sm text-text-muted">Unavailable in the current session response.</p>
          </div>
        </article>
      </section>

      <section className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:gap-6" aria-label="Session evidence">
        <article className="ui-panel flex min-h-[300px] flex-col overflow-hidden xl:col-span-8">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border bg-surface px-5 py-4 sm:px-6">
            <div>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
                <Terminal className="h-4 w-4" aria-hidden="true" />
                Evidence stream
              </div>
              <h2 className="mt-1 text-base font-semibold sm:text-lg">Live interaction shell</h2>
            </div>
            <span className="ui-badge">Not available</span>
          </div>
          <div className="flex flex-1 items-center p-5 sm:p-6">
            <RegionState kind="empty" title="Interaction evidence unavailable" description="Command history is not included in the current session response." />
          </div>
        </article>

        <article className="ui-panel flex min-h-[300px] flex-col p-5 sm:p-6 xl:col-span-4">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            Analysis
          </div>
          <h2 className="mt-1 text-base font-semibold sm:text-lg">Predict next step</h2>
          <div className="mt-6 flex flex-1 items-center">
            <RegionState kind="empty" title="Prediction unavailable" description="No predictive assessment is included in the current session response." />
          </div>
        </article>
      </section>

      <section className="ui-panel overflow-hidden" aria-labelledby="hypothesis-title">
        <div className="border-b border-border bg-surface px-5 py-4 sm:px-6">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.12em] text-primary">
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
            Evidence summary
          </div>
          <h2 id="hypothesis-title" className="mt-1 text-base font-semibold sm:text-lg">Threat hypothesis summary</h2>
        </div>
        <div className="p-5 sm:p-6">
          <p className="rounded-lg border border-border bg-surface-subtle p-4 text-sm leading-6 text-text-muted">No evidence-backed summary is available in the current session response.</p>
        </div>
      </section>
    </div>
  );
}

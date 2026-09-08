"use client";
import { useMemo, useState } from "react";
import TargetLandscapeChart from "@/components/threat-intel/TargetLandscapeChart";
import Link from "next/link";
import { useThreatFeed } from "@/components/threat/ThreatFeedProvider";
import type { DashboardChartDatum } from "@/lib/dashboardTypes";
import { RefreshStatus, RegionState } from "@/components/ui/RegionState";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { classificationBadgeClass } from "@/lib/presentation";

export default function ThreatIntelPage() {
  const { threats: logs, status } = useThreatFeed();

  // กำหนดให้แสดงสูงสุด 5 รายการต่อหน้า
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 5;

  const stats = useMemo(() => ({
    total: logs.length,
    proxies: logs.filter((entry) => entry.classification === "BOT").length,
    critical: logs.filter((entry) => entry.severity === "Critical" || entry.severity === "High").length,
  }), [logs]);
  const chartData = useMemo<DashboardChartDatum[]>(() => {
    const aptCount = logs.filter((entry) => entry.classification === "APT").length;
    const botCount = logs.filter((entry) => entry.classification === "BOT").length;
    const scriptCount = logs.filter((entry) => entry.classification === "SCRIPT KIDDIE").length;
    return [
      { name: "APT", value: aptCount, color: "var(--chart-4)" },
      { name: "Bot", value: botCount, color: "var(--chart-2)" },
      { name: "Script", value: scriptCount, color: "var(--neutral)" },
      { name: "Other", value: logs.length - (aptCount + botCount + scriptCount), color: "var(--chart-3)" },
    ];
  }, [logs]);

  const totalPages = Math.ceil(logs.length / itemsPerPage);
  const currentLogs = logs.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

  const getPageNumbers = () => {
    let start = Math.max(1, currentPage - 2);
    const end = Math.min(totalPages, start + 4);
    if (end - start < 4) start = Math.max(1, end - 4);
    return Array.from({ length: Math.max(0, end - start + 1) }, (_, i) => start + i);
  };

  // ใช้ข้อมูลเปอร์เซ็นต์จริงสำหรับแสดงคำบรรยายใต้แผนภูมิ
  const getPercent = (val: number) => stats.total > 0 ? Math.round((val / stats.total) * 100) : 0;
  const isInitialLoad = status === "loading";
  const isUnavailable = status === "error";

  return (
    <div className="space-y-6 pb-8">
      <section aria-label="Threat intelligence overview" aria-busy={isInitialLoad} className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricSummary label="Total sessions" value={stats.total.toLocaleString()} loading={isInitialLoad} unavailable={isUnavailable} />
        <MetricSummary label="Automated bots" value={stats.proxies.toString()} loading={isInitialLoad} unavailable={isUnavailable} annotation="Detected" annotationClass="text-warning" />
        <MetricSummary label="Detection latency" value="Unavailable" loading={isInitialLoad} unavailable={isUnavailable} reported={false} />
        <MetricSummary label="Critical threats" value={stats.critical.toString().padStart(2, "0")} loading={isInitialLoad} unavailable={isUnavailable} annotation="Critical severity" annotationClass="text-danger" valueClass="text-danger" />
      </section>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <div className="ui-panel flex min-h-[340px] flex-col p-5 sm:p-6 xl:col-span-4">
          <div className="mb-3 flex items-start justify-between gap-4">
            <div><h2 className="text-base font-semibold">Target landscape</h2><p className="mt-1 text-xs text-text-muted">Classification distribution</p></div>
            <RefreshStatus status={status} />
          </div>
          <div className="min-h-0 flex-1">
            {isInitialLoad && <RegionState kind="loading" title="Loading threat distribution" />}
            {isUnavailable && <RegionState kind="error" title="Distribution unavailable" description="The latest session directory could not be loaded." />}
            {!isInitialLoad && !isUnavailable && <div className="flex h-full flex-col justify-between">
              <div className="mx-auto w-full max-w-[230px]"><TargetLandscapeChart data={chartData} total={stats.total} /></div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-3 border-t border-border pt-4 text-xs text-text-muted">
                <LegendItem color="var(--chart-4)" label={`APT (${chartData[0]?.value ? getPercent(chartData[0].value) : 0}%)`} />
                <LegendItem color="var(--chart-2)" label={`Bot (${chartData[1]?.value ? getPercent(chartData[1].value) : 0}%)`} />
                <LegendItem color="var(--neutral)" label={`Script (${chartData[2]?.value ? getPercent(chartData[2].value) : 0}%)`} />
                <LegendItem color="var(--chart-3)" label={`Other (${chartData[3]?.value ? getPercent(chartData[3].value) : 0}%)`} />
              </div>
            </div>}
          </div>
        </div>

        <div className="ui-panel flex min-h-[340px] flex-col overflow-hidden xl:col-span-8">
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border p-5 sm:p-6">
            <div>
              <h2 className="text-base font-semibold">Live incursion log</h2>
              <p className="mt-1 text-xs text-text-muted">Real-time packet interception and origin analysis.</p>
            </div>
            <RefreshStatus status={status} />
          </div>

          <div className="relative min-h-0 flex-1" aria-busy={status === "loading" || status === "refreshing"}>
            <div className="ui-scroll-region h-full" role="region" aria-label="Live incursion log. Scroll to view all columns." tabIndex={0}>
            <table className="ui-table min-w-[760px]">
              <thead>
                <tr>
                  <th scope="col">Timestamp</th>
                  <th scope="col">Hacker IP</th>
                  <th scope="col">Classification</th>
                  <th scope="col">Severity</th>
                  <th scope="col" className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {isInitialLoad && Array.from({ length: itemsPerPage }, (_, index) => (
                  <tr key={`loading-${index}`} aria-hidden="true">
                    {Array.from({ length: 5 }, (_, column) => <td key={column}><div className="ui-skeleton h-4 w-full" /></td>)}
                  </tr>
                ))}
                {!isInitialLoad && currentLogs.map((log) => (
                  <tr key={log.id} className="text-text-muted">
                    <td className="font-mono text-xs">
                      <div>{log.date}</div>
                      <div className="mt-1 text-text-subtle">{log.time}</div>
                    </td>
                    <td className="font-mono text-xs text-text">{log.sourceIp}</td>
                    <td>
                      <span className={`ui-badge ${classificationBadgeClass(log.typeColor)}`}>
                        {log.classification}
                      </span>
                    </td>
                    <td><SeverityBadge severity={log.severity} /></td>
                    <td className="text-right">
                      <Link href={`/threat-intel/${log.id}`} className="ui-button min-h-9 px-3 text-xs">
                        View Details
                      </Link>
                    </td>
                  </tr>
                ))}
                {/* สร้างช่องว่างให้เต็ม 5 แถวเสมอเมื่อข้อมูลหน้าสุดท้ายไม่ถึง 5 รายการ */}
                {!isInitialLoad && Array.from({ length: Math.max(0, itemsPerPage - currentLogs.length) }).map((_, idx) => (
                  <tr key={`empty-${idx}`}>
                    <td colSpan={5}></td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>

            <div className="pointer-events-none absolute inset-x-0 top-[52px] bottom-0 [&>div]:h-full">
              {status === "error" && <RegionState kind="error" title="Threat intelligence unavailable" description="The latest session directory could not be loaded. The next automatic refresh will try again." />}
              {status === "ready" && logs.length === 0 && <RegionState kind="empty" title="NO THREAT INTELLIGENCE AVAILABLE" description="No sessions were returned in the last successful response." />}
            </div>

          </div>
          {!isInitialLoad && totalPages > 1 && (
              <nav aria-label="Incursion log pages" className="flex flex-wrap justify-end gap-2 border-t border-border bg-surface-subtle p-4">
                <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p - 1)} className="ui-button min-h-9 px-3 text-xs">Prev</button>
                {getPageNumbers().map(pageNum => (
                  <button key={pageNum} onClick={() => setCurrentPage(pageNum)} aria-current={currentPage === pageNum ? "page" : undefined} aria-label={`Page ${pageNum}`} className="ui-button min-h-9 px-3 text-xs">
                    {pageNum}
                  </button>
                ))}
                <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p + 1)} className="ui-button min-h-9 px-3 text-xs">Next</button>
              </nav>
          )}
        </div>
      </section>
    </div>
  );
}

function MetricSummary({ label, value, loading, unavailable, reported = true, annotation, annotationClass = "text-text-subtle", valueClass = "text-text" }: { label: string; value: string; loading: boolean; unavailable: boolean; reported?: boolean; annotation?: string; annotationClass?: string; valueClass?: string }) {
  return <div className="ui-panel flex min-h-[116px] flex-col justify-between p-5">
    <h2 className="text-sm font-medium text-text-muted">{label}</h2>
    {loading ? <div className="ui-skeleton h-8 w-20" aria-label={`Loading ${label}`} /> : unavailable || !reported ? <p className="text-sm text-text-muted">{reported ? "Unavailable" : "Not reported"}</p> : <div className="flex flex-wrap items-baseline gap-2"><span className={`text-[28px] font-semibold leading-9 tabular-nums ${valueClass}`}>{value}</span>{annotation && <span className={`text-xs font-medium ${annotationClass}`}>{annotation}</span>}</div>}
  </div>;
}

function LegendItem({ color, label }: { color: string; label: string }) {
  return <span className="flex items-center gap-2"><span aria-hidden="true" className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />{label}</span>;
}

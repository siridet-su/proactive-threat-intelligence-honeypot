import { AlertCircle, Inbox, Radio, RefreshCw } from "lucide-react";
import {
  ChartLaserLoader,
  MapRadarLoader,
  TableStreamSkeleton,
  TerminalStreamLoader,
  TopologyCanvasLoader,
} from "@/components/ui/loaders";

export type RegionStatus = "loading" | "ready" | "refreshing" | "error" | "stale";
export type RegionVariant = "general" | "table" | "chart" | "terminal" | "map" | "topology";

export interface RefreshStatusProps {
  /** สถานะปัจจุบันของการรีเฟรชข้อมูล (เช่น กำลังรีเฟรช, หรือข้อมูลเก่าเพราะรีเฟรชไม่ผ่าน) */
  status: RegionStatus;
}

/**
 * คอมโพเนนต์สำหรับแสดงข้อความสถานะการอัปเดตข้อมูลขนาดเล็ก (มุมมอง Indicator)
 * จะแสดงผลข้อความและไอคอนเฉพาะเมื่อสถานะเป็น "refreshing" หรือ "stale"
 * 
 * @param {RefreshStatusProps} props - สถานะที่ต้องการแสดงผล
 */
export function RefreshStatus({ status }: RefreshStatusProps) {
  return (
    <span role="status" className="inline-flex min-h-5 items-center gap-2 text-xs text-text-muted font-mono">
      {status === "refreshing" && (
        <>
          <RefreshCw className="h-3.5 w-3.5 animate-spin text-primary" aria-hidden="true" />
          <span className="text-primary font-medium">Refreshing telemetry…</span>
        </>
      )}
      {status === "stale" && (
        <>
          <AlertCircle className="h-3.5 w-3.5 text-warning" aria-hidden="true" />
          Refresh failed · showing last successful result
        </>
      )}
    </span>
  );
}

export interface RegionStateProps {
  /** รูปแบบของสถานะหน้าจอที่ต้องการแสดง (กำลังโหลด, เกิดข้อผิดพลาด, หรือไม่มีข้อมูล) */
  kind: "loading" | "error" | "empty";
  /** ข้อความหัวข้อหลักที่จะแสดงบนหน้าจอ */
  title: string;
  /** คำอธิบายเพิ่มเติม (Optional) */
  description?: string;
  /** รูปแบบดีไซน์ของ loading state เฉพาะทาง (เช่น table, chart, terminal, map, topology) */
  variant?: RegionVariant;
}

/**
 * คอมโพเนนต์สำหรับแสดงสถานะของพื้นที่หน้าจอขนาดใหญ่ (State Placeholder)
 * เช่น โครงร่างการโหลดข้อมูล (Skeleton/Loader), กล่องข้อความแจ้งเตือนข้อผิดพลาด, หรือแจ้งว่าไม่มีข้อมูล
 * 
 * @param {RegionStateProps} props - ข้อมูลรูปแบบ ข้อความ คำอธิบาย และประเภท variant
 */
export function RegionState({ kind, title, description, variant = "general" }: RegionStateProps) {
  if (kind === "loading") {
    if (variant === "map") {
      return <MapRadarLoader title={title} subtitle={description} />;
    }
    if (variant === "chart") {
      return <ChartLaserLoader title={title} />;
    }
    if (variant === "terminal") {
      return <TerminalStreamLoader title={title} subtitle={description} />;
    }
    if (variant === "table") {
      return <TableStreamSkeleton />;
    }
    if (variant === "topology") {
      return <TopologyCanvasLoader title={title} subtitle={description} />;
    }
  }

  const Icon = kind === "error" ? AlertCircle : Inbox;
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      aria-busy={kind === "loading"}
      className={`flex min-h-40 flex-col items-center justify-center gap-3 rounded-xl p-6 text-center ${
        kind === "error" ? "bg-danger-subtle border border-danger-border/40" : "bg-surface-subtle border border-border/50"
      }`}
    >
      {kind === "loading" ? (
        <div aria-hidden="true" className="w-full max-w-sm space-y-3.5 flex flex-col items-center">
          <div className="relative flex items-center justify-center">
            <span className="absolute h-8 w-8 rounded-full bg-primary/25 animate-ping" />
            <span className="relative flex h-9 w-9 items-center justify-center rounded-xl border border-primary-border bg-primary-subtle text-primary shadow-xs">
              <Radio className="h-4 w-4 animate-spin text-primary" />
            </span>
          </div>
          <div className="w-full space-y-2">
            <div className="ui-skeleton h-3.5 w-3/4 mx-auto" />
            <div className="ui-skeleton h-3 w-1/2 mx-auto opacity-75" />
          </div>
        </div>
      ) : (
        <Icon aria-hidden="true" className={`h-6 w-6 ${kind === "error" ? "text-danger" : "text-text-subtle"}`} />
      )}
      <p className="font-semibold text-text tracking-tight text-sm sm:text-base">{title}</p>
      {description && <p className="max-w-md text-xs text-text-muted leading-relaxed">{description}</p>}
    </div>
  );
}
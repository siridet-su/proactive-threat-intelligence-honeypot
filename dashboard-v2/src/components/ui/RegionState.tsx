import { AlertCircle, Inbox, RefreshCw } from "lucide-react";

export type RegionStatus = "loading" | "ready" | "refreshing" | "error" | "stale";

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
    <span role="status" className="inline-flex min-h-5 items-center gap-2 text-xs text-text-muted">
      {status === "refreshing" && (
        <>
          <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
          Refreshing…
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
}

/**
 * คอมโพเนนต์สำหรับแสดงสถานะของพื้นที่หน้าจอขนาดใหญ่ (State Placeholder)
 * เช่น โครงร่างการโหลดข้อมูล (Skeleton), กล่องข้อความแจ้งเตือนข้อผิดพลาด, หรือแจ้งว่าไม่มีข้อมูล
 * 
 * @param {RegionStateProps} props - ข้อมูลรูปแบบ ข้อความ และคำอธิบาย
 */
export function RegionState({ kind, title, description }: RegionStateProps) {
  const Icon = kind === "error" ? AlertCircle : Inbox;
  return (
    <div
      role={kind === "error" ? "alert" : "status"}
      aria-busy={kind === "loading"}
      className={`flex min-h-40 flex-col items-center justify-center gap-3 rounded-lg p-6 text-center ${
        kind === "error" ? "bg-danger-subtle" : "bg-surface-subtle"
      }`}
    >
      {kind === "loading" ? (
        <div aria-hidden="true" className="w-full max-w-sm space-y-3">
          <div className="ui-skeleton h-3 w-2/3" />
          <div className="ui-skeleton h-3" />
          <div className="ui-skeleton h-3 w-4/5" />
        </div>
      ) : (
        <Icon aria-hidden="true" className={`h-5 w-5 ${kind === "error" ? "text-danger" : "text-text-subtle"}`} />
      )}
      <p className="font-medium text-text">{title}</p>
      {description && <p className="max-w-md text-sm text-text-muted">{description}</p>}
    </div>
  );
}
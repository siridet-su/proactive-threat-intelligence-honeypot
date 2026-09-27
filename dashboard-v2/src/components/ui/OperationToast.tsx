"use client";

import { motion, useReducedMotion } from "framer-motion";
import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";

export type OperationToastKind = "success" | "error" | "info";

export interface OperationToastProps {
  /** ประเภทของการแจ้งเตือน */
  kind: OperationToastKind;
  /** หัวข้อหลักของการแจ้งเตือน */
  title: string;
  /** คำอธิบายรายละเอียดเพิ่มเติม */
  description: string;
  /** ฟังก์ชันที่จะถูกเรียกเมื่อผู้ใช้กดปุ่มปิด (กากบาท) */
  onDismiss: () => void;
  actionLabel?: string;
  onAction?: () => void;
  dismissible?: boolean;
}

/**
 * คอมโพเนนต์สำหรับแสดงข้อความแจ้งเตือนผลการทำงาน (Toast Notification)
 * รองรับการแสดงผลแบบสำเร็จ ข้อมูล และข้อผิดพลาด
 * มีการจัดการเรื่อง Accessibility (role และ aria-live) อย่างถูกต้อง
 * 
 * @param {OperationToastProps} props - ข้อมูลและฟังก์ชันที่ใช้ควบคุม Toast
 */
export function OperationToast({ kind, title, description, onDismiss, actionLabel, onAction, dismissible = true }: OperationToastProps) {
  const success = kind === "success";
  const info = kind === "info";
  const reducedMotion = useReducedMotion();

  return (
    <motion.aside
      initial={reducedMotion ? false : { opacity: 0, x: 420 }}
      animate={{ opacity: 1, x: 0 }}
      exit={reducedMotion ? { opacity: 0 } : { opacity: 0, x: 420, transition: { duration: 0.2 } }}
      transition={reducedMotion ? { duration: 0 } : { duration: 0.32, ease: [0.22, 1, 0.36, 1] }}
      className={`fixed bottom-4 right-4 z-[140] flex w-[calc(100vw-2rem)] max-w-sm items-start gap-3 rounded-xl border p-4 shadow-[var(--shadow-raised)] sm:bottom-5 sm:right-5 ${
        success ? "border-success-border bg-success-subtle" : info ? "border-info-border bg-info-subtle" : "border-danger-border bg-danger-subtle"
      }`}
      role={kind === "error" ? "alert" : "status"}
      aria-live={kind === "error" ? "assertive" : "polite"}
    >
      {success ? (
        <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-success" aria-hidden="true" />
      ) : info ? (
        <Info className="mt-0.5 h-5 w-5 shrink-0 text-info" aria-hidden="true" />
      ) : (
        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-danger" aria-hidden="true" />
      )}
      <div className="min-w-0 flex-1">
        <p className="font-semibold text-text">{title}</p>
        <p className="mt-1 text-sm leading-5 text-text-muted">{description}</p>
      </div>
      {(actionLabel && onAction || dismissible) && <div className="flex shrink-0 items-center self-center">
        {actionLabel && onAction && <button type="button" className="min-h-9 rounded-lg border border-info-border bg-surface px-3 text-sm font-semibold text-info transition-colors hover:bg-info-subtle focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info" onClick={onAction}>{actionLabel}</button>}
        {dismissible && <button
          type="button"
          className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-border bg-surface text-text-muted transition-colors hover:bg-surface-subtle hover:text-text focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-info"
          onClick={onDismiss}
          aria-label="Dismiss notification"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>}
      </div>}
    </motion.aside>
  );
}

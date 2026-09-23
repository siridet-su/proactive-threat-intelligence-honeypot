"use client";

import { AlertCircle, CheckCircle2, X } from "lucide-react";

export type OperationToastKind = "success" | "error";

export interface OperationToastProps {
  /** ประเภทของการแจ้งเตือน (สำเร็จ หรือ ผิดพลาด) */
  kind: OperationToastKind;
  /** หัวข้อหลักของการแจ้งเตือน */
  title: string;
  /** คำอธิบายรายละเอียดเพิ่มเติม */
  description: string;
  /** ฟังก์ชันที่จะถูกเรียกเมื่อผู้ใช้กดปุ่มปิด (กากบาท) */
  onDismiss: () => void;
}

/**
 * คอมโพเนนต์สำหรับแสดงข้อความแจ้งเตือนผลการทำงาน (Toast Notification)
 * รองรับการแสดงผลทั้งแบบสำเร็จ (Success) และข้อผิดพลาด (Error)
 * มีการจัดการเรื่อง Accessibility (role และ aria-live) อย่างถูกต้อง
 * 
 * @param {OperationToastProps} props - ข้อมูลและฟังก์ชันที่ใช้ควบคุม Toast
 */
export function OperationToast({ kind, title, description, onDismiss }: OperationToastProps) {
  const success = kind === "success";
  
  return (
    <aside
      className={`fixed bottom-5 right-5 z-[140] flex w-[calc(100%-2rem)] max-w-sm gap-3 rounded-xl border p-4 shadow-[var(--shadow-raised)] motion-safe:animate-[pti-hero-enter_180ms_ease-out] ${
        success ? "border-success-border bg-success-subtle" : "border-danger-border bg-danger-subtle"
      }`}
      role={success ? "status" : "alert"}
      aria-live={success ? "polite" : "assertive"}
    >
      {success ? (
        <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-success" aria-hidden="true" />
      ) : (
        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-danger" aria-hidden="true" />
      )}
      
      <div className="min-w-0 flex-1">
        <p className="font-semibold text-text">{title}</p>
        <p className="mt-1 text-sm leading-5 text-text-muted">{description}</p>
      </div>
      
      <button 
        type="button" 
        className="ui-button min-h-8 shrink-0 px-1.5" 
        onClick={onDismiss} 
        aria-label="Dismiss notification"
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </button>
    </aside>
  );
}
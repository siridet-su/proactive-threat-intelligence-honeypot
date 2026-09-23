import { RiskLevel } from "@/types/honeypot";

/**
 * คืนค่า CSS classes สำหรับสร้าง Badge แสดงระดับความรุนแรง (Severity)
 * 
 * @param {RiskLevel | string} severity - ระดับความรุนแรง (Critical, High, Medium, Low)
 * @returns {string} CSS classes สำหรับ Tailwind เพื่อใช้สร้าง Badge
 */
export function severityBadgeClass(severity: RiskLevel | string): string {
  switch (severity) {
    case "Critical":
      return "bg-severity-critical-subtle text-severity-critical border-severity-critical-border";
    case "High":
      return "bg-severity-high-subtle text-severity-high border-severity-high-border";
    case "Medium":
      return "bg-severity-medium-subtle text-severity-medium border-severity-medium-border";
    case "Low":
      return "bg-severity-low-subtle text-severity-low border-severity-low-border";
    default:
      return "bg-neutral-subtle text-neutral border-neutral-border";
  }
}

/**
 * คืนค่า CSS class สำหรับสีของจุดสถานะ (Status Dot) เช่น การแสดงสถานะหน้า Session ID
 * 
 * @param {RiskLevel | string} severity - ระดับความรุนแรง
 * @returns {string} CSS background class สำหรับจุดสถานะ
 */
export function severityDotClass(severity: RiskLevel | string): string {
  switch (severity) {
    case "Critical":
      return "bg-severity-critical";
    case "High":
      return "bg-severity-high";
    case "Medium":
      return "bg-severity-medium";
    case "Low":
      return "bg-severity-low";
    default:
      return "bg-neutral";
  }
}

/**
 * คืนค่า CSS class สำหรับแถบสถานะ (Status Bar) 
 * 
 * @param {RiskLevel | string} severity - ระดับความรุนแรง
 * @returns {string} CSS background class
 */
export function severityBarClass(severity: RiskLevel | string): string {
  return severityDotClass(severity);
}

/**
 * คืนค่ารหัสสีดิบ (CSS Variable) สำหรับนำไปใช้กับ Map Pins, Canvas หรือ Charts
 * 
 * @param {RiskLevel | string} severity - ระดับความรุนแรง
 * @returns {string} CSS Variable ของสีนั้นๆ
 */
export function severityColor(severity: RiskLevel | string): string {
  switch (severity) {
    case "Critical":
      return "var(--severity-critical)";
    case "High":
      return "var(--severity-high)";
    case "Medium":
      return "var(--severity-medium)";
    case "Low":
      return "var(--severity-low)";
    default:
      return "var(--neutral)";
  }
}

/**
 * คืนค่า CSS classes สำหรับ Badge จัดกลุ่มประเภทผู้โจมตี (Classification)
 * มีการจัดการกับข้อมูลแบบเก่าที่อาจส่งมาเป็นโค้ดสี (Legacy typeColor) ด้วย
 * 
 * @param {string} [classificationOrColor] - ประเภทผู้โจมตี (เช่น APT, BOT) หรือสี
 * @param {string} [typeColor] - สีแบบเก่า (Legacy text color)
 * @returns {string} CSS classes สำหรับ Badge ของกลุ่มผู้โจมตี
 */
export function classificationBadgeClass(classificationOrColor?: string, typeColor?: string): string {
  const val = classificationOrColor || "";
  const norm = val.trim().toUpperCase();

  if (norm.includes("APT")) {
    return "bg-chart-4-subtle text-chart-4 border-chart-4-border";
  }
  if (norm.includes("BOT") || norm.includes("PROXY")) {
    return "bg-chart-2-subtle text-chart-2 border-chart-2-border";
  }
  if (norm.includes("SCRIPT") || norm.includes("KIDDIE")) {
    return "bg-neutral-subtle text-neutral border-neutral-border";
  }
  if (norm.includes("OTHER")) {
    return "bg-chart-3-subtle text-chart-3 border-chart-3-border";
  }

  // Fallback สำหรับ Legacy color strings
  const checkColor = typeColor || val;
  if (checkColor.includes("text-red-400")) return "bg-severity-critical-subtle text-severity-critical border-severity-critical-border";
  if (checkColor.includes("text-amber-400")) return "bg-severity-medium-subtle text-severity-medium border-severity-medium-border";

  return "bg-neutral-subtle text-neutral border-neutral-border";
}

/**
 * คืนค่า CSS classes สำหรับ Badge ระบุประเภทของมัลแวร์ใน Malware Vault
 * 
 * @param {string} type - ประเภทของไฟล์หรือ Artifact
 * @returns {string} CSS classes สำหรับ Malware Type Badge
 */
export function malwareTypeBadgeClass(type: string): string {
  if (type.includes("Malicious IP")) {
    return "bg-danger-subtle text-danger border-danger-border";
  }
  if (type.includes("Download") || type.includes("Payload")) {
    return "bg-info-subtle text-info border-info-border";
  }
  return "bg-neutral-subtle text-neutral border-neutral-border";
}
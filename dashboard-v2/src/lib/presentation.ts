import { RiskLevel } from "@/types/honeypot";

/**
 * Standard badge classes for risk / severity levels across all views.
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
 * Color class for status dots (e.g. Session ID leading indicator)
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
 * Color class for status bars (e.g. Priority Queue item leading bar)
 */
export function severityBarClass(severity: RiskLevel | string): string {
  return severityDotClass(severity);
}

/**
 * Raw CSS variable for map pins / inline canvas / charts
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
 * Classification badge styling aligned with Target Landscape chart colors:
 * - APT: Purple (chart-4)
 * - BOT: Teal (chart-2)
 * - SCRIPT KIDDIE: Slate (neutral)
 * - Other / Fallback: Amber (chart-3)
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

  // Fallback check if classificationOrColor was a legacy typeColor string
  const checkColor = typeColor || val;
  if (checkColor.includes("text-red-400")) return "bg-severity-critical-subtle text-severity-critical border-severity-critical-border";
  if (checkColor.includes("text-amber-400")) return "bg-severity-medium-subtle text-severity-medium border-severity-medium-border";

  return "bg-neutral-subtle text-neutral border-neutral-border";
}

/**
 * Badge styling for malware vault artifact types.
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

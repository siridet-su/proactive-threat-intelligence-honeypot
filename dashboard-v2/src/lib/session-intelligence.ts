export type IntelligenceRecord = Record<string, unknown>;

export const SAFE_PROVIDER_CONTEXT_KEYS = new Set([
  "malicious",
  "suspicious",
  "harmless",
  "undetected",
  "timeout",
  "detection_numerator",
  "detection_denominator",
  "meaningful_name",
  "type",
  "reputation_label",
  "pulses",
  "asn",
  "organization",
  "isp",
  "country",
  "ports",
  "services",
  "cpe",
  "vulnerabilities",
  "tags",
  "hostnames",
  "last_update",
  "abuse_confidence_score",
  "total_reports",
  "categories",
  "usage_type",
  "country_code",
  "last_reported_at",
]);

export function intelligenceRecord(value: unknown): IntelligenceRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as IntelligenceRecord
    : {};
}

function isRedactionMarker(value: string): boolean {
  return value.trim().toUpperCase() === "[REDACTED]";
}

export function analystCommandText(value: unknown): string | null {
  if (typeof value === "string") {
    return value.trim() && !isRedactionMarker(value) ? value : null;
  }
  const item = intelligenceRecord(value);
  for (const key of ["command_text", "input", "command", "text", "source_command"]) {
    const candidate = item[key];
    if (typeof candidate === "string" && candidate.trim() && !isRedactionMarker(candidate)) {
      return candidate;
    }
  }
  return null;
}

export function analystAttackerUsername(value: unknown): string | null {
  const item = intelligenceRecord(value);
  if (String(item.username_visibility || "").toUpperCase() !== "AVAILABLE") return null;
  const candidate = item.attacker_username;
  return typeof candidate === "string" && candidate.trim() && !isRedactionMarker(candidate)
    ? candidate
    : null;
}

function providerValue(value: unknown): string {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value
      .filter((item) => typeof item === "string" || typeof item === "number" || typeof item === "boolean")
      .slice(0, 12)
      .map(String)
      .join(", ");
  }
  return "";
}

export function selectedProviderFields(value: unknown): Array<readonly [string, string]> {
  return Object.entries(intelligenceRecord(value))
    .filter(([key]) => SAFE_PROVIDER_CONTEXT_KEYS.has(key))
    .map(([key, item]) => [key, providerValue(item)] as const)
    .filter(([, rendered]) => rendered.length > 0);
}

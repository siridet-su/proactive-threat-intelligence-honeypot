export type IntelligenceRecord = Record<string, unknown>;

export type EnsembleEvidenceState =
  | "AGREE"
  | "DISAGREE"
  | "MODEL1_ONLY"
  | "MODEL2_ONLY"
  | "MODEL2_UNAVAILABLE"
  | "MODEL1_NOT_APPLICABLE";

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

export function ensembleEvidenceState(value: unknown): EnsembleEvidenceState {
  const item = intelligenceRecord(value);
  const model1 = intelligenceRecord(item.s1_advisory);
  const model2 = intelligenceRecord(item.shadow_model);
  const model1Technique = String(model1.predicted_technique || "").trim();
  const model2Technique = String(model2.technique_id || "").trim();
  const model1Status = String(model1.status || "").toLowerCase();
  const model2Status = String(model2.status || "").toLowerCase();
  const model1NotApplicable = ["not_applicable", "skipped", "short_input_skipped"].includes(model1Status);
  const model2Unavailable = ["unavailable", "error", "missing"].includes(model2Status);

  if (model1NotApplicable) return "MODEL1_NOT_APPLICABLE";
  if (model1Technique && model2Technique) {
    return model1Technique === model2Technique ? "AGREE" : "DISAGREE";
  }
  if (model1Technique) return model2Unavailable ? "MODEL2_UNAVAILABLE" : "MODEL1_ONLY";
  if (model2Technique) return "MODEL2_ONLY";

  // Compatibility for older stored classification records that predate the
  // explicit per-model projection.
  const agreement = String(item.agreement_status || "").toLowerCase();
  const source = String(item.source || "").toLowerCase();

  if (agreement === "not_applicable" || source === "shell_noise") return "MODEL1_NOT_APPLICABLE";
  if (agreement === "exact_technique_agreement" || source === "both") return "AGREE";
  if (agreement.includes("disagreement") || source === "rule_securebert_disagreement") return "DISAGREE";
  if (source === "securebert_unavailable" || model2Unavailable) return "MODEL2_UNAVAILABLE";
  if (agreement === "model_only" || source === "securebert") return "MODEL2_ONLY";
  return "MODEL1_ONLY";
}

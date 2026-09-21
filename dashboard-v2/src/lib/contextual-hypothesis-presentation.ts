type JsonRecord = Record<string, unknown>;

export interface ContextualHypothesisRow {
  key: string;
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  ruleId: string;
  sourceType: string;
  claimStatus: string;
  matchedConditions: Array<{ type: string; description: string }>;
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedText(value: unknown, maximum = 240): string {
  return typeof value === "string" && value.trim()
    ? value.trim().slice(0, maximum)
    : "";
}

/**
 * Project only non-sensitive, display-safe fields from contextual TTP
 * correlations. In particular, raw `evidence`, `reason`, and command fields
 * are omitted because a matched evidence record may contain attacker input.
 */
export function projectContextualHypotheses(value: unknown): ContextualHypothesisRow[] {
  if (!Array.isArray(value)) return [];

  return value.slice(0, 20).flatMap((candidate, index) => {
    if (!isRecord(candidate)) return [];
    const predicted = isRecord(candidate.predicted_technique) ? candidate.predicted_technique : {};
    const techniqueId = boundedText(candidate.main_ttp || predicted.main_ttp || candidate.ttp, 32);
    const techniqueName = boundedText(predicted.technique_name || candidate.technique_name);
    const ruleId = boundedText(candidate.rule_id, 128);
    const correlationId = boundedText(candidate.correlation_id, 128);
    const matchedConditions = Array.isArray(candidate.matched_conditions)
      ? candidate.matched_conditions.slice(0, 8).flatMap((item) => {
          if (!isRecord(item)) return [];
          const condition = isRecord(item.condition) ? item.condition : {};
          const description = boundedText(item.description);
          const type = boundedText(condition.type, 64);
          return description || type ? [{ type, description }] : [];
        }).slice(0, 4)
      : [];

    return [{
      key: correlationId || ruleId || `${techniqueId || "context"}-${index}`,
      techniqueId,
      techniqueName,
      tactic: boundedText(predicted.tactic || candidate.tactic, 64),
      ruleId,
      sourceType: boundedText(candidate.source_type, 64),
      claimStatus: boundedText(candidate.claim_status, 64) || "CONTEXTUAL_ONLY",
      matchedConditions,
    }];
  }).slice(0, 10);
}

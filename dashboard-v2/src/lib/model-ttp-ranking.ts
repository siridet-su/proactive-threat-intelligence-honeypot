type JsonRecord = Record<string, unknown>;

const SHARED_MODEL2_TECHNIQUES = new Set(["T1105", "T1046", "T1110"]);
const VALID_MODEL2_STATUSES = new Set(["VALID_SHADOW", "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW"]);

/** Frozen Model1 38-label names from the repository's Enterprise ATT&CK v14.1 cache. */
const MODEL1_TECHNIQUE_NAMES: Readonly<Record<string, string>> = Object.freeze({
  T1003: "OS Credential Dumping",
  T1005: "Data from Local System",
  T1007: "System Service Discovery",
  T1011: "Exfiltration Over Other Network Medium",
  T1016: "System Network Configuration Discovery",
  T1018: "Remote System Discovery",
  T1021: "Remote Services",
  T1033: "System Owner/User Discovery",
  T1040: "Network Sniffing",
  T1046: "Network Service Discovery",
  T1049: "System Network Connections Discovery",
  T1053: "Scheduled Task/Job",
  T1057: "Process Discovery",
  T1059: "Command and Scripting Interpreter",
  T1068: "Exploitation for Privilege Escalation",
  T1069: "Permission Groups Discovery",
  T1070: "Indicator Removal",
  T1078: "Valid Accounts",
  T1082: "System Information Discovery",
  T1083: "File and Directory Discovery",
  T1098: "Account Manipulation",
  T1105: "Ingress Tool Transfer",
  T1110: "Brute Force",
  T1114: "Email Collection",
  T1125: "Video Capture",
  T1136: "Create Account",
  T1222: "File and Directory Permissions Modification",
  T1518: "Software Discovery",
  T1548: "Abuse Elevation Control Mechanism",
  T1550: "Use Alternate Authentication Material",
  T1552: "Unsecured Credentials",
  T1556: "Modify Authentication Process",
  T1560: "Archive Collected Data",
  T1567: "Exfiltration Over Web Service",
  T1569: "System Services",
  T1570: "Lateral Tool Transfer",
  T1572: "Protocol Tunneling",
  T1654: "Log Enumeration",
});

export function model1TechniqueName(techniqueId: string): string {
  return MODEL1_TECHNIQUE_NAMES[techniqueId.trim().toUpperCase()] ?? "";
}

function object(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : {};
}

function nonempty(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/** Model2 may corroborate only after all production binding identities match. */
export function hasBoundModel2(data: JsonRecord): boolean {
  const ensemble = object(data.ensemble_evidence);
  const model2 = object(ensemble.model2);
  const binding = object(model2.binding);
  const sessionId = nonempty(data.session_id) || nonempty(object(data.overview).session_id);
  const runId = nonempty(ensemble.run_id);
  const measurementId = nonempty(model2.measurement_id);
  const episodeId = nonempty(model2.episode_id);
  return model2.available === true
    && (!nonempty(ensemble.session_id) || nonempty(ensemble.session_id) === sessionId)
    && VALID_MODEL2_STATUSES.has(nonempty(model2.status))
    && Boolean(sessionId && runId && measurementId && episodeId)
    && nonempty(binding.session_id) === sessionId
    && nonempty(binding.run_id) === runId
    && nonempty(binding.measurement_id) === measurementId
    && nonempty(binding.episode_id) === episodeId
    && Boolean(nonempty(model2.artifact_sha256) && nonempty(model2.feature_contract_sha256));
}

export interface TtpRecommendation {
  techniqueId: string;
  rank: number;
  supportingCommandEvents: number;
  assessedCommandEvents: number;
  evidenceRefs: Array<{ commandRef: string; evidenceId: string; observedAt: string }>;
  model2Support: "corroborates" | "does_not_support" | "unavailable" | "not_supported";
  rankingScore: number | null;
  model2RankingComponent: number;
  model2SupportAdded: boolean;
  exclusionReason: string;
  baselineRank: number;
}

/** Read the server-owned weighted-voting projection; never rank by raw model scores. */
export function rankTtpRecommendations(data: JsonRecord): TtpRecommendation[] {
  const advisory = object(data.session_ttp_advisory);
  const sessionId = nonempty(data.session_id) || nonempty(object(data.overview).session_id);
  if (advisory.schema_version !== "session_model1_ttp_advisory.v1"
    || advisory.session_id !== sessionId || advisory.authority !== "ADVISORY_ONLY"
    || !Array.isArray(advisory.techniques)) return [];
  const assessed = advisory.assessed_command_events;
  if (!Number.isSafeInteger(assessed) || (assessed as number) < 0) return [];
  const weighted = object(advisory.weighted_voting_recommendation);
  const weightedRows = Array.isArray(weighted.rows) ? weighted.rows.map(object) : [];
  const weightedOrder = Array.isArray(weighted.recommendation_order)
    ? weighted.recommendation_order.map(nonempty) : [];
  const baselineOrder = advisory.techniques.map(object).map((item) => nonempty(item.technique_id));
  const validWeighted = weighted.schema_version === "session_ttp_weighted_voting_advisory.v1"
    && weighted.session_id === sessionId
    && weighted.method === "evidence_gated_weighted_voting"
    && weighted.candidate_set_source === "MODEL1_ONLY"
    && weighted.score_semantics === "VOTE_SCORE_NOT_PROBABILITY_OR_CONFIDENCE"
    && weightedRows.length === baselineOrder.length
    && weightedOrder.length === baselineOrder.length
    && new Set(weightedOrder).size === baselineOrder.length
    && new Set(weightedRows.map((row) => nonempty(row.technique_id))).size === baselineOrder.length
    && baselineOrder.every((technique) => weightedOrder.includes(technique)
      && weightedRows.some((row) => nonempty(row.technique_id) === technique));
  const rowsByTechnique = validWeighted
    ? new Map(weightedRows.map((row) => [nonempty(row.technique_id), row]))
    : new Map<string, JsonRecord>();
  return advisory.techniques.map(object).flatMap((item) => {
    const techniqueId = nonempty(item.technique_id);
    const count = item.supporting_command_events;
    if (!/^T\d{4}(?:\.\d{3})?$/.test(techniqueId)
      || !Number.isSafeInteger(count) || (count as number) < 1 || (count as number) > (assessed as number)) return [];
    const weightedRow = rowsByTechnique.get(techniqueId);
    const model2SupportAdded = weightedRow?.model2_support_added === true;
    const model2Support: TtpRecommendation["model2Support"] = !SHARED_MODEL2_TECHNIQUES.has(techniqueId)
      ? "not_supported"
      : weightedRow ? model2SupportAdded ? "corroborates"
        : weightedRow.eligible === true && weightedRow.model2_decision === "ABSENT" ? "does_not_support"
        : "unavailable"
      : "unavailable";
    const evidenceRefs = Array.isArray(item.evidence_refs) ? item.evidence_refs.map(object).map((ref) => ({
      commandRef: nonempty(ref.command_ref),
      evidenceId: nonempty(ref.evidence_id),
      observedAt: nonempty(ref.observed_at),
    })).filter((ref) => ref.commandRef) : [];
    return [{ techniqueId, rank: 0, supportingCommandEvents: count as number,
      assessedCommandEvents: assessed as number, evidenceRefs, model2Support,
      rankingScore: typeof weightedRow?.weighted_vote_score === "number" ? weightedRow.weighted_vote_score : null,
      model2RankingComponent: typeof weightedRow?.model2_vote_component === "number" ? weightedRow.model2_vote_component : 0,
      model2SupportAdded,
      exclusionReason: nonempty(weightedRow?.exclusion_reason),
      baselineRank: typeof weightedRow?.baseline_rank === "number" ? weightedRow.baseline_rank : 0,
    }];
  }).sort((a, b) => validWeighted
    ? weightedOrder.indexOf(a.techniqueId) - weightedOrder.indexOf(b.techniqueId)
    : b.supportingCommandEvents - a.supportingCommandEvents || a.techniqueId.localeCompare(b.techniqueId))
    .map((item, index) => ({ ...item, rank: index + 1, baselineRank: item.baselineRank || index + 1 }));
}

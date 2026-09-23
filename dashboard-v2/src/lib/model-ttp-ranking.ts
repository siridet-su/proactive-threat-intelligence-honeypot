type JsonRecord = Record<string, unknown>;

const SHARED_MODEL2_TECHNIQUES = new Set(["T1105", "T1046", "T1110"]);
const VALID_MODEL2_STATUSES = new Set(["VALID_SHADOW", "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW"]);

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
}

/** Read the server's deduplicated command-level advisory; never rank by margins. */
export function rankTtpRecommendations(data: JsonRecord): TtpRecommendation[] {
  const advisory = object(data.session_ttp_advisory);
  const sessionId = nonempty(data.session_id) || nonempty(object(data.overview).session_id);
  if (advisory.schema_version !== "session_model1_ttp_advisory.v1"
    || advisory.session_id !== sessionId || advisory.authority !== "ADVISORY_ONLY"
    || !Array.isArray(advisory.techniques)) return [];
  const ensemble = object(data.ensemble_evidence);
  const model2Bound = hasBoundModel2(data);
  const results = Array.isArray(ensemble.results) ? ensemble.results.map(object) : [];
  const byTechnique = new Map(results.map((item) => [nonempty(item.technique_id), item]));
  const assessed = advisory.assessed_command_events;
  if (!Number.isSafeInteger(assessed) || (assessed as number) < 0) return [];
  return advisory.techniques.map(object).flatMap((item) => {
    const techniqueId = nonempty(item.technique_id);
    const count = item.supporting_command_events;
    if (!/^T\d{4}(?:\.\d{3})?$/.test(techniqueId)
      || !Number.isSafeInteger(count) || (count as number) < 1 || (count as number) > (assessed as number)) return [];
    const comparison = byTechnique.get(techniqueId);
    const model2Support: TtpRecommendation["model2Support"] = !SHARED_MODEL2_TECHNIQUES.has(techniqueId)
      ? "not_supported"
      : !model2Bound || comparison?.model2_available !== true
        ? "unavailable"
        : comparison.model2_result === "PRESENT"
          ? "corroborates"
          : comparison.model2_result === "ABSENT"
            ? "does_not_support"
            : "unavailable";
    const evidenceRefs = Array.isArray(item.evidence_refs) ? item.evidence_refs.map(object).map((ref) => ({
      commandRef: nonempty(ref.command_ref),
      evidenceId: nonempty(ref.evidence_id),
      observedAt: nonempty(ref.observed_at),
    })).filter((ref) => ref.commandRef) : [];
    return [{ techniqueId, rank: 0, supportingCommandEvents: count as number,
      assessedCommandEvents: assessed as number, evidenceRefs, model2Support }];
  }).sort((a, b) => b.supportingCommandEvents - a.supportingCommandEvents || a.techniqueId.localeCompare(b.techniqueId))
    .map((item, index) => ({ ...item, rank: index + 1 }));
}

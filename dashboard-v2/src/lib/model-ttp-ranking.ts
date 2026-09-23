type JsonRecord = Record<string, unknown>;

const RRF_K = 60;
const SHARED_MODEL2_TECHNIQUES = new Set(["T1105", "T1046", "T1110"]);
const VALID_MODEL2_STATUSES = new Set([
  "VALID_SHADOW",
  "MODEL2_V5_STYLE_UNIFIED_PRODUCTION_NATIVE_SHADOW",
]);

function object(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as JsonRecord
    : {};
}

function nonempty(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function technique(value: unknown): string {
  const id = nonempty(value);
  return /^T\d{4}$/.test(id) ? id : "";
}

/** Model2 may contribute only after all production binding identities match. */
export function hasRankableModel2(data: JsonRecord): boolean {
  const ensemble = object(data.ensemble_evidence);
  const model2 = object(ensemble.model2);
  const binding = object(model2.binding);
  const sessionId = nonempty(data.session_id) || nonempty(object(data.overview).session_id);
  const runId = nonempty(ensemble.run_id);
  const measurementId = nonempty(model2.measurement_id);
  const episodeId = nonempty(model2.episode_id);
  return model2.available === true
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
  model1Rank: number;
  model1Margin: number | null;
  model2Support: "corroborates" | "contradicts" | "unavailable";
  score: number;
}

/** RRF-style advisory priority, not a calibrated confidence or trusted finding. */
export function rankTtpRecommendations(data: JsonRecord): TtpRecommendation[] {
  const ensemble = object(data.ensemble_evidence);
  if (object(ensemble.model1).applicable !== true) return [];
  const shared = Array.isArray(ensemble.results) ? ensemble.results.map(object) : [];
  const model1Only = Array.isArray(ensemble.model1_only_labels)
    ? ensemble.model1_only_labels.map(object)
    : [];
  const candidates = new Map<string, { margin: number | null; model2Result: string }>();
  for (const item of [...shared, ...model1Only]) {
    const id = technique(item.technique_id);
    if (!id || !(item.model1_result === "PRESENT" || item.model1_result === undefined && item.result === "PRESENT")) continue;
    const margin = finite(item.model1_margin ?? item.decision_score);
    const prior = candidates.get(id);
    if (!prior || margin !== null && (prior.margin === null || margin > prior.margin)) {
      candidates.set(id, {
        margin,
        model2Result: SHARED_MODEL2_TECHNIQUES.has(id) ? nonempty(item.model2_result) : "",
      });
    }
  }
  const ordered = [...candidates.entries()].sort((a, b) => {
    if (a[1].margin === null && b[1].margin !== null) return 1;
    if (a[1].margin !== null && b[1].margin === null) return -1;
    return (b[1].margin ?? 0) - (a[1].margin ?? 0) || a[0].localeCompare(b[0]);
  });
  const validModel2 = hasRankableModel2(data);
  return ordered.map(([techniqueId, item], index) => {
    const model1Rank = index + 1;
    const model2Support: TtpRecommendation["model2Support"] = validModel2 && item.model2Result === "PRESENT"
      ? "corroborates"
      : validModel2 && item.model2Result === "ABSENT"
        ? "contradicts"
        : "unavailable";
    // Model2's independent technique decisions have no validated cross-head
    // ranking. Treat all PRESENT outputs as tied at rank 1; never compare raw scores.
    const score = 1 / (RRF_K + model1Rank)
      + (model2Support === "corroborates" ? 1 / (RRF_K + 1) : 0);
    return { techniqueId, rank: 0, model1Rank, model1Margin: item.margin, model2Support, score };
  }).sort((a, b) => b.score - a.score || a.model1Rank - b.model1Rank || a.techniqueId.localeCompare(b.techniqueId))
    .map((item, index) => ({ ...item, rank: index + 1 }));
}

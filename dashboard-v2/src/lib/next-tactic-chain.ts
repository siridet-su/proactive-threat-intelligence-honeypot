export type NextTacticChainStep = {
  tactic: string;
  kind: "observed" | "predicted" | "historical";
};

type Forecast = {
  tactic?: unknown;
  historical?: boolean;
} | null;

function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function tacticText(value: unknown): string {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

/**
 * Build the analyst-facing sequence without treating a forecast as an
 * observation. The backend path is already ordered and coalesced; this
 * helper only adds one explicitly labelled next-tactic result when valid.
 */
export function buildNextTacticChain(
  observedPath: unknown,
  forecast: Forecast = null,
): NextTacticChainStep[] {
  const chain: NextTacticChainStep[] = [];
  if (Array.isArray(observedPath)) {
    for (const item of observedPath) {
      const tactic = tacticText(record(item).tactic);
      if (tactic) chain.push({ tactic, kind: "observed" });
    }
  }
  const forecastTactic = tacticText(forecast?.tactic);
  if (forecastTactic) {
    chain.push({
      tactic: forecastTactic,
      kind: forecast?.historical ? "historical" : "predicted",
    });
  }
  return chain;
}

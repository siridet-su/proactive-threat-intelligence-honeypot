import "server-only";

const SESSION_ID_PATTERN = /^[0-9a-f]{12}$/;
const ACTION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const AGENT_TIMEOUT_MS = 4_000;

export type ResponseAgentResult =
  | { delivered: true; status: "terminating" }
  | { delivered: false; category: "not_found" | "unconfigured" | "unavailable" | "rejected" };

export function responseControlConfigured(): boolean {
  return Boolean(process.env.COWRIE_RESPONSE_AGENT_URL?.trim() && (process.env.COWRIE_RESPONSE_AGENT_TOKEN?.trim().length ?? 0) >= 32);
}

function isPrivateManagementHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host.endsWith(".ts.net") || host.startsWith("[fd7a:115c:a1e0:")) return true;
  const octets = host.split(".").map(Number);
  return octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127;
}

function responseAgentEndpoint(sessionId: string): URL {
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new Error("invalid Cowrie session id");
  const configured = process.env.COWRIE_RESPONSE_AGENT_URL?.trim();
  if (!configured) throw new Error("response agent is not configured");
  const base = new URL(configured);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new Error("response agent URL is invalid");
  }
  if (base.protocol === "http:" && !isPrivateManagementHost(base.hostname)) {
    throw new Error("unencrypted response agent URL must use a private management host");
  }
  return new URL(`/v1/sessions/${sessionId}/terminate`, base);
}

export async function requestSessionTermination(sessionId: string, actionId: string): Promise<ResponseAgentResult> {
  const token = process.env.COWRIE_RESPONSE_AGENT_TOKEN?.trim();
  if (!token || !responseControlConfigured()) return { delivered: false, category: "unconfigured" };
  if (!ACTION_ID_PATTERN.test(actionId)) return { delivered: false, category: "rejected" };

  let endpoint: URL;
  try {
    endpoint = responseAgentEndpoint(sessionId);
  } catch {
    return { delivered: false, category: "unconfigured" };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AGENT_TIMEOUT_MS);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      cache: "no-store",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Action-ID": actionId,
      },
      signal: controller.signal,
    });
    if (response.status === 404) return { delivered: false, category: "not_found" };
    if (!response.ok) return { delivered: false, category: response.status >= 500 ? "unavailable" : "rejected" };
    const document: unknown = await response.json();
    if (!document || typeof document !== "object" || (document as { status?: unknown }).status !== "terminating") {
      return { delivered: false, category: "rejected" };
    }
    return { delivered: true, status: "terminating" };
  } catch {
    return { delivered: false, category: "unavailable" };
  } finally {
    clearTimeout(timeout);
  }
}

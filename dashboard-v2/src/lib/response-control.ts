import "server-only";

import { lstatSync, readFileSync } from "node:fs";
import { isAbsolute } from "node:path";

const SESSION_ID_PATTERN = /^[0-9a-f]{12}$/;
const ACTION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const AGENT_TIMEOUT_MS = 4_000;
const MIN_TOKEN_LENGTH = 32;
const MAX_TOKEN_BYTES = 4_096;

export type ResponseAgentResult =
  | { delivered: true; status: "terminating" }
  | { delivered: false; category: "not_found" | "unconfigured" | "unavailable" | "rejected" };

function validBearerToken(value: string): string | null {
  const token = value.trim();
  if (token.length < MIN_TOKEN_LENGTH || Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES) return null;
  if (/[\s\u0000-\u001f\u007f]/u.test(token)) return null;
  return token;
}

function tokenFromPrivateFile(configuredPath: string): string | null {
  const tokenPath = configuredPath.trim();
  if (!tokenPath || !isAbsolute(tokenPath)) return null;
  try {
    const stat = lstatSync(/* turbopackIgnore: true */ tokenPath);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size > MAX_TOKEN_BYTES) return null;
    return validBearerToken(readFileSync(/* turbopackIgnore: true */ tokenPath, {
      encoding: "utf8",
      flag: "r",
    }));
  } catch {
    return null;
  }
}

function responseAgentToken(): string | null {
  const tokenFile = process.env.COWRIE_RESPONSE_AGENT_TOKEN_FILE;
  if (tokenFile?.trim()) return tokenFromPrivateFile(tokenFile);
  return validBearerToken(process.env.COWRIE_RESPONSE_AGENT_TOKEN ?? "");
}

export function responseControlConfigured(): boolean {
  return Boolean(process.env.COWRIE_RESPONSE_AGENT_URL?.trim() && responseAgentToken());
}

function isPrivateManagementHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (host === "localhost" || host === "127.0.0.1" || host.endsWith(".ts.net") || host.startsWith("[fd7a:115c:a1e0:")) return true;
  const octets = host.split(".").map(Number);
  return octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127;
}

function responseAgentEndpoint(sessionId: string): URL {
  if (!SESSION_ID_PATTERN.test(sessionId)) throw new Error("invalid Cowrie session id");
  return new URL(`/v1/sessions/${sessionId}/terminate`, responseAgentBase());
}

function responseAgentBase(): URL {
  const configured = process.env.COWRIE_RESPONSE_AGENT_URL?.trim();
  if (!configured) throw new Error("response agent is not configured");
  const base = new URL(configured);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) {
    throw new Error("response agent URL is invalid");
  }
  if (base.protocol === "http:" && !isPrivateManagementHost(base.hostname)) {
    throw new Error("unencrypted response agent URL must use a private management host");
  }
  return base;
}

export async function responseControlHealthy(): Promise<boolean> {
  const token = responseAgentToken();
  if (!token) return false;
  let endpoint: URL;
  try {
    endpoint = new URL("/v1/health", responseAgentBase());
  } catch {
    return false;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AGENT_TIMEOUT_MS);
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      cache: "no-store",
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const document: unknown = await response.json();
    return Boolean(document && typeof document === "object" && (document as { ok?: unknown }).ok === true && (document as { status?: unknown }).status === "ready");
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

export async function requestSessionTermination(sessionId: string, actionId: string): Promise<ResponseAgentResult> {
  const token = responseAgentToken();
  if (!token || !process.env.COWRIE_RESPONSE_AGENT_URL?.trim()) return { delivered: false, category: "unconfigured" };
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

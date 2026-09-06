export const SESSION_COOKIE_NAME = "pti_session";

export type SessionRole = "Admin" | "Supporter";

export interface SignedSessionPayload {
  sessionId: string;
  operatorId: string;
  role: SessionRole;
  mustChangePassword: boolean;
  expiresAt: number;
}

const DEVELOPMENT_ONLY_SECRET = "pti-dashboard-development-only-secret-do-not-use-in-production";
let developmentSecretWarningIssued = false;

function getSecret(): string {
  const secret = process.env.AUTH_SESSION_SECRET;
  if (!secret && process.env.NODE_ENV === "development") {
    if (!developmentSecretWarningIssued) {
      console.warn("[auth] AUTH_SESSION_SECRET is missing; using the development-only session secret.");
      developmentSecretWarningIssued = true;
    }
    return DEVELOPMENT_ONLY_SECRET;
  }
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SESSION_SECRET must be set to a random value of at least 32 characters.");
  }
  return secret;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function signingKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(new TextEncoder().encode(getSecret())),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function isPayload(value: unknown): value is SignedSessionPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const payload = value as Record<string, unknown>;
  return typeof payload.sessionId === "string" && payload.sessionId.length > 0 &&
    typeof payload.operatorId === "string" && payload.operatorId.length > 0 &&
    (payload.role === "Admin" || payload.role === "Supporter") &&
    typeof payload.mustChangePassword === "boolean" &&
    typeof payload.expiresAt === "number" && Number.isFinite(payload.expiresAt);
}

export async function signSessionToken(payload: SignedSessionPayload): Promise<string> {
  const encodedPayload = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", await signingKey(), toArrayBuffer(new TextEncoder().encode(encodedPayload)));
  return `${encodedPayload}.${toBase64Url(new Uint8Array(signature))}`;
}

export async function verifySessionToken(token: string | undefined): Promise<SignedSessionPayload | null> {
  if (!token) return null;
  const [encodedPayload, encodedSignature, ...extra] = token.split(".");
  if (!encodedPayload || !encodedSignature || extra.length) return null;

  try {
    const valid = await crypto.subtle.verify(
      "HMAC",
      await signingKey(),
      toArrayBuffer(fromBase64Url(encodedSignature)),
      toArrayBuffer(new TextEncoder().encode(encodedPayload)),
    );
    if (!valid) return null;

    const payload: unknown = JSON.parse(new TextDecoder().decode(toArrayBuffer(fromBase64Url(encodedPayload))));
    return isPayload(payload) && payload.expiresAt > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

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

/**
 * ดึงค่า Secret Key สำหรับใช้เซ็น Token 
 * หากไม่ได้ตั้งค่าใน Production ระบบจะแจ้ง Error เพื่อความปลอดภัย
 * 
 * @returns {string} - Secret Key ที่มีความยาวอย่างน้อย 32 ตัวอักษร
 */
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

/**
 * แปลงข้อมูลไบต์ (Uint8Array) เป็นสตริง Base64Url ที่ปลอดภัยสำหรับใช้ใน URL/Cookie
 * 
 * @param {Uint8Array} bytes - ข้อมูลที่ต้องการแปลง
 * @returns {string} - สตริงรูปแบบ Base64Url
 */
function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * แปลงสตริง Base64Url กลับเป็นข้อมูลไบต์ (Uint8Array)
 * 
 * @param {string} value - สตริงรูปแบบ Base64Url
 * @returns {Uint8Array} - ข้อมูลไบต์ต้นฉบับ
 */
function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/**
 * แปลง Uint8Array เป็น ArrayBuffer เพื่อให้รองรับกับ Web Crypto API
 * 
 * @param {Uint8Array} bytes - ข้อมูลไบต์
 * @returns {ArrayBuffer} - ข้อมูล ArrayBuffer
 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/**
 * นำ Secret Key มาสร้างเป็น CryptoKey สำหรับใช้ทำ HMAC SHA-256
 * 
 * @returns {Promise<CryptoKey>} - คีย์สำหรับเข้ารหัส/ตรวจสอบ
 */
async function signingKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(new TextEncoder().encode(getSecret())),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/**
 * Type Guard เพื่อตรวจสอบว่าข้อมูล Payload มีโครงสร้างที่ถูกต้องหรือไม่
 * 
 * @param {unknown} value - ข้อมูลที่ดึงมาจาก Token
 * @returns {boolean} - true หากข้อมูลครบและถูกต้องตาม Interface SignedSessionPayload
 */
function isPayload(value: unknown): value is SignedSessionPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const payload = value as Record<string, unknown>;
  return typeof payload.sessionId === "string" && payload.sessionId.length > 0 &&
    typeof payload.operatorId === "string" && payload.operatorId.length > 0 &&
    (payload.role === "Admin" || payload.role === "Supporter") &&
    typeof payload.mustChangePassword === "boolean" &&
    typeof payload.expiresAt === "number" && Number.isFinite(payload.expiresAt);
}

/**
 * สร้างและเซ็น Session Token ด้วยอัลกอริทึม HMAC SHA-256
 * 
 * @param {SignedSessionPayload} payload - ข้อมูลผู้ใช้ที่ต้องการบรรจุลงใน Token
 * @returns {Promise<string>} - Token ในรูปแบบ `Base64Url(Payload).Base64Url(Signature)`
 */
export async function signSessionToken(payload: SignedSessionPayload): Promise<string> {
  const encodedPayload = toBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign(
    "HMAC", 
    await signingKey(), 
    toArrayBuffer(new TextEncoder().encode(encodedPayload))
  );
  return `${encodedPayload}.${toBase64Url(new Uint8Array(signature))}`;
}

/**
 * ตรวจสอบความถูกต้องของ Token (ลายเซ็น, วันหมดอายุ, โครงสร้าง)
 * 
 * @param {string | undefined} token - Token ที่ได้รับจาก Cookie
 * @returns {Promise<SignedSessionPayload | null>} - ข้อมูลผู้ใช้หาก Token ถูกต้อง, หรือ null หากไม่ถูกต้อง
 */
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
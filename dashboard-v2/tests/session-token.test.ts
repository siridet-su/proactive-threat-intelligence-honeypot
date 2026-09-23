import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { signSessionToken, verifySessionToken, type SignedSessionPayload } from "../src/lib/auth/session-token";

describe("session-token.ts", () => {
  const validPayload: SignedSessionPayload = {
    sessionId: "sess-12345",
    operatorId: "admin_01",
    role: "Admin",
    mustChangePassword: false,
    // ตั้งเวลาหมดอายุให้เป็น 1 ชั่วโมงข้างหน้า
    expiresAt: Date.now() + 60 * 60 * 1000, 
  };

  beforeEach(() => {
    // จำลอง Environment Variable ให้มีความยาวเกิน 32 ตัวอักษรตามที่ระบบต้องการ
    vi.stubEnv("AUTH_SESSION_SECRET", "this-is-a-very-secure-secret-key-that-is-at-least-32-chars-long");
  });

  afterEach(() => {
    // เคลียร์ค่าที่จำลองไว้ออกไป เพื่อไม่ให้กระทบเทสต์ไฟล์อื่น
    vi.unstubAllEnvs();
  });

  it("ควรเซ็น Token และตรวจสอบกลับคืนเป็น Payload เดิมได้ (Round-trip)", async () => {
    const token = await signSessionToken(validPayload);
    
    expect(typeof token).toBe("string");
    // Token ต้องมี 2 ส่วนคั่นด้วยจุด: Payload.Signature
    expect(token.split(".")).toHaveLength(2); 

    const verified = await verifySessionToken(token);
    expect(verified).toEqual(validPayload);
  });

  it("ควรคืนค่า null หาก Token ถูกปลอมแปลงหรือแก้ไข (Invalid Signature)", async () => {
    const token = await signSessionToken(validPayload);
    
    // แยกส่วน Payload และ Signature ออกจากกัน (คั่นด้วยจุด)
    const [payload, signature] = token.split(".");
    
    // เปลี่ยนตัวอักษร "ตัวแรก" ของ Signature แทน เพื่อให้ข้อมูลไบต์เปลี่ยนไปอย่างแน่นอน
    const tamperedSignature = (signature.startsWith("A") ? "B" : "A") + signature.slice(1);
    const tamperedToken = `${payload}.${tamperedSignature}`;

    const verified = await verifySessionToken(tamperedToken);
    expect(verified).toBeNull();
  });

  it("ควรคืนค่า null หาก Token หมดอายุแล้ว", async () => {
    const expiredPayload: SignedSessionPayload = {
      ...validPayload,
      // ตั้งเวลาหมดอายุเป็นอดีต (1 วินาทีที่แล้ว)
      expiresAt: Date.now() - 1000, 
    };

    const token = await signSessionToken(expiredPayload);
    const verified = await verifySessionToken(token);
    
    // ลายเซ็นถูก แต่เวลาหมดอายุ ต้องคืนค่า null
    expect(verified).toBeNull();
  });

  it("ควรคืนค่า null หากรูปแบบ Token ผิดพลาด (Malformed)", async () => {
    expect(await verifySessionToken("not-a-valid-token")).toBeNull();
    expect(await verifySessionToken("part1.part2.part3")).toBeNull(); // มี 3 ส่วนผิดรูปแบบ
    expect(await verifySessionToken("")).toBeNull();
    expect(await verifySessionToken(undefined)).toBeNull();
  });
});
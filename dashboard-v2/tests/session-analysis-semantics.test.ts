import { describe, expect, it } from "vitest";
import {
  authoritativeEventTimestamp,
  chronologicalRecords,
  sessionLifecycleStatus,
} from "../src/lib/session-analysis-semantics";

describe("session-analysis-semantics.ts", () => {
  describe("authoritativeEventTimestamp", () => {
    it("ควรดึงฟิลด์ timestamp ออกมาก่อนถ้ามี", () => {
      const record = { timestamp: "2026-09-16T12:00:00Z", received_at: "2026-09-16T12:01:00Z" };
      expect(authoritativeEventTimestamp(record)).toBe("2026-09-16T12:00:00Z");
    });

    it("ควรตกไปใช้ฟิลด์สำรอง (fallback) หากฟิลด์หลักไม่มี", () => {
      const record = { updated_at: "2026-09-16T12:05:00Z" };
      expect(authoritativeEventTimestamp(record)).toBe("2026-09-16T12:05:00Z");
    });
  });

  describe("chronologicalRecords", () => {
    it("ควรจัดเรียงเหตุการณ์ตามเวลาได้อย่างถูกต้อง", () => {
      const events = [
        { id: 2, timestamp: "2026-09-16T12:05:00Z" },
        { id: 1, timestamp: "2026-09-16T12:00:00Z" },
        { id: 3, timestamp: "2026-09-16T12:10:00Z" },
      ];
      const sorted = chronologicalRecords(events);
      expect(sorted[0].id).toBe(1);
      expect(sorted[1].id).toBe(2);
      expect(sorted[2].id).toBe(3);
    });

    it("หากเวลาเท่ากัน ควรใช้ sequence เป็นตัวตัดสิน", () => {
      const events = [
        { id: "B", timestamp: "1000", sequence: 2 },
        { id: "A", timestamp: "1000", sequence: 1 },
      ];
      const sorted = chronologicalRecords(events);
      expect(sorted[0].id).toBe("A");
      expect(sorted[1].id).toBe("B");
    });

    it("หากเวลาและ sequence เท่ากัน/ไม่มีข้อมูล ควรยึดลำดับเดิม (Stable sort)", () => {
      const events = [
        { id: "First", noTime: true },
        { id: "Second", noTime: true },
      ];
      const sorted = chronologicalRecords(events);
      expect(sorted[0].id).toBe("First");
      expect(sorted[1].id).toBe("Second");
    });
  });

  describe("sessionLifecycleStatus", () => {
    it("ควรประเมินสถานะเป็น 'Closed' ถ้าระบุว่าจบแล้ว (is_ended = true)", () => {
      const detail = { session: { is_ended: true } };
      expect(sessionLifecycleStatus(detail)).toBe("Closed");
    });

    it("ควรประเมินสถานะเป็น 'Closed' ถ้าพบวันที่ปิด session (ended_at)", () => {
      const detail = { overview: { ended_at: "2026-09-16T12:00:00Z" } };
      expect(sessionLifecycleStatus(detail)).toBe("Closed");
    });

    it("ควรประเมินสถานะเป็น 'Closed' จาก status text", () => {
      const detail = { status: "TERMINATED" }; // ทดสอบความสามารถรองรับเคสตัวพิมพ์ใหญ่-เล็ก
      expect(sessionLifecycleStatus(detail)).toBe("Closed");
    });

    it("ควรประเมินสถานะเป็น 'Active' หากพบว่ากำลังทำงาน", () => {
      const detail = { session_payload: { status: "connected" } };
      expect(sessionLifecycleStatus(detail)).toBe("Active");
    });

    it("ควรประเมินสถานะเป็น 'Unknown' หากไม่มีข้อมูลเพียงพอ", () => {
      const detail = { session: { status: "pending_review" } };
      expect(sessionLifecycleStatus(detail)).toBe("Unknown");
    });
  });
});
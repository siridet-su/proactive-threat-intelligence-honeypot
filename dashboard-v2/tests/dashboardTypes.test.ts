import { describe, expect, it } from "vitest";
import {
  isDashboardThreatEvent,
  isHardwareTelemetry,
  parseHardwareStreamMessage,
  parseThreatStreamMessage,
  formatHardwareMetric,
  numericHardwareMetric,
  isDashboardUser
} from "../src/lib/dashboardTypes";

describe("dashboardTypes.ts - Type Guards", () => {
  describe("isDashboardThreatEvent", () => {
    const validEvent = {
      id: "evt-123",
      timestamp: Date.now(),
      date: "2026-09-16",
      time: "12:00:00",
      sensor: "cowrie",
      src_ip: "192.168.1.1",
      sourceIp: "192.168.1.1",
      severity: "High",
      classification: "Bot",
      typeColor: "red",
      duration: "10s",
      geo: { lat: 10, lon: 20, country: "TH", city: "BKK" },
    };

    it("ควรคืนค่า true สำหรับ Event ที่มีโครงสร้างสมบูรณ์", () => {
      expect(isDashboardThreatEvent(validEvent)).toBe(true);
    });

    it("ควรคืนค่า false หากฟิลด์บังคับขาดหายไป", () => {
      const missingGeo = { ...validEvent } as Record<string, unknown>;
      delete missingGeo.geo;
      expect(isDashboardThreatEvent(missingGeo)).toBe(false);
    });

    it("ควรคืนค่า false หากเป็นข้อมูลผิดประเภท (เช่น Array หรือ null)", () => {
      expect(isDashboardThreatEvent(null)).toBe(false);
      expect(isDashboardThreatEvent([])).toBe(false);
    });
  });

  describe("numericHardwareMetric", () => {
    it("ควรแปลง string ตัวเลขให้เป็น number ได้", () => {
      expect(numericHardwareMetric("45.5")).toBe(45.5);
      expect(numericHardwareMetric(45.5)).toBe(45.5);
    });

    it("ควรคืนค่า null สำหรับข้อมูลขยะหรือค่าว่าง", () => {
      expect(numericHardwareMetric(null)).toBeNull();
      expect(numericHardwareMetric("")).toBeNull();
      expect(numericHardwareMetric("not_a_number")).toBeNull();
    });
  });

  describe("isHardwareTelemetry & formatHardwareMetric", () => {
    const validTelemetry = {
      timestamp: "2026-09-16T12:00:00Z",
      cpu_percent: "50",
      mem_percent: 60,
    };

    it("ควรรับรอง Telemetry ที่มี timestamp และตัวเลข (หรือสตริงตัวเลข)", () => {
      expect(isHardwareTelemetry(validTelemetry)).toBe(true);
    });

    it("formatHardwareMetric ควรแปลงเวลาและ Metric เป็นตัวเลขสำหรับ Chart", () => {
      const formatted = formatHardwareMetric(validTelemetry);
      expect(formatted.cpu_percent).toBe(50); // แปลงจาก string เป็น number
      expect(formatted.mem_percent).toBe(60);
      expect(typeof formatted.time).toBe("string"); // "19:00:00" (ขึ้นอยู่กับ Timezone)
      expect(formatted.timestampEpoch).toBeGreaterThan(0);
    });
  });

  describe("Stream Message Parsers", () => {
    it("parseThreatStreamMessage ควรแยกแยะ snapshot และ upsert ได้", () => {
      expect(parseThreatStreamMessage({ type: "snapshot", data: [] })).toEqual({ type: "snapshot", data: [] });
      expect(parseThreatStreamMessage({ type: "heartbeat", data: { at: "now" } })).toEqual({ type: "heartbeat", data: { at: "now" } });
      
      // ข้อมูลผิดพลาด
      expect(parseThreatStreamMessage({ type: "unknown" })).toBeNull();
      expect(parseThreatStreamMessage("string_data")).toBeNull();
    });

    it("parseHardwareStreamMessage ควรตรวจสอบ initial และ update ได้", () => {
      const telemetry = { timestamp: Date.now(), cpu_percent: 10 };
      expect(parseHardwareStreamMessage({ type: "initial", data: [telemetry] })).toEqual({ type: "initial", data: [telemetry] });
      expect(parseHardwareStreamMessage({ type: "update", data: telemetry })).toEqual({ type: "update", data: telemetry });
      
      // ส่ง Object เปล่าๆ เข้า update ควรถูกปฏิเสธ (ไม่ใช่ Telemetry ที่สมบูรณ์)
      expect(parseHardwareStreamMessage({ type: "update", data: {} })).toBeNull();
    });
  });

  describe("isDashboardUser", () => {
    it("ควรตรวจสอบฟิลด์ของผู้ใช้งานได้", () => {
      const validUser = {
        operatorId: "admin_01",
        fullName: "System Admin",
        email: "admin@example.com",
        position: "Security Analyst",
        role: "Admin",
        status: "Active"
      };
      expect(isDashboardUser(validUser)).toBe(true);
      expect(isDashboardUser({ ...validUser, role: 123 })).toBe(false); // role ผิดประเภท
    });
  });
});
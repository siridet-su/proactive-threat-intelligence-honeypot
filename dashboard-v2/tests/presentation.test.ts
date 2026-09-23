import { describe, expect, it } from "vitest";
import {
  severityBadgeClass,
  severityColor,
  classificationBadgeClass,
  malwareTypeBadgeClass
} from "../src/lib/presentation";

describe("presentation.ts utility functions", () => {

  describe("severityBadgeClass", () => {
    it("ควรคืนค่าคลาสสีแดง (Critical) เมื่อรับค่า 'Critical'", () => {
      expect(severityBadgeClass("Critical")).toContain("text-severity-critical");
    });

    it("ควรคืนค่าคลาสสีเหลือง (Medium) เมื่อรับค่า 'Medium'", () => {
      expect(severityBadgeClass("Medium")).toContain("text-severity-medium");
    });

    it("ควรคืนค่าคลาสแบบเป็นกลาง (Neutral) เมื่อรับค่าที่ไม่รู้จัก", () => {
      expect(severityBadgeClass("UnknownValue")).toContain("text-neutral");
    });
  });

  describe("severityColor", () => {
    it("ควรคืนค่า CSS Variable ที่ถูกต้องตามระดับความเสี่ยง", () => {
      expect(severityColor("High")).toBe("var(--severity-high)");
      expect(severityColor("Low")).toBe("var(--severity-low)");
    });
    
    it("ควรคืนค่า --neutral เมื่อไม่มีข้อมูลตรงตามเงื่อนไข", () => {
      expect(severityColor("")).toBe("var(--neutral)");
    });
  });

  describe("classificationBadgeClass", () => {
    it("ควรคืนค่าคลาสสีม่วง (Chart 4) เมื่อพบคำว่า 'APT'", () => {
      expect(classificationBadgeClass("APT Group 33")).toContain("text-chart-4");
    });

    it("ควรคืนค่าคลาสสีเขียว (Chart 2) เมื่อพบคำว่า 'BOT' หรือ 'PROXY'", () => {
      expect(classificationBadgeClass("botnet")).toContain("text-chart-2");
      expect(classificationBadgeClass("Proxy Server")).toContain("text-chart-2");
    });

    it("ควรคืนค่าคลาสสีกลางๆ เมื่อพบคำว่า 'SCRIPT KIDDIE'", () => {
      expect(classificationBadgeClass("Script Kiddie")).toContain("text-neutral");
    });

    it("ควรรองรับการส่งค่า Legacy สี (typeColor) เป็น Fallback", () => {
      expect(classificationBadgeClass("Unknown", "text-red-400")).toContain("text-severity-critical");
      expect(classificationBadgeClass("", "text-amber-400")).toContain("text-severity-medium");
    });
  });

  describe("malwareTypeBadgeClass", () => {
    it("ควรคืนค่าคลาส Danger (สีแดง) สำหรับ 'Malicious IP'", () => {
      expect(malwareTypeBadgeClass("Known Malicious IP")).toContain("text-danger");
    });

    it("ควรคืนค่าคลาส Info (สีฟ้า) สำหรับ 'Download' หรือ 'Payload'", () => {
      expect(malwareTypeBadgeClass("File Download")).toContain("text-info");
      expect(malwareTypeBadgeClass("Exploit Payload")).toContain("text-info");
    });

    it("ควรคืนค่าคลาส Neutral สำหรับประเภทอื่นๆ", () => {
      expect(malwareTypeBadgeClass("Text Log")).toContain("text-neutral");
    });
  });

});
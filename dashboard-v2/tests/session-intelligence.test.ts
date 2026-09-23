import { describe, expect, it } from "vitest";
import {
  analystCommandText,
  analystAttackerUsername,
  selectedProviderFields,
  ensembleEvidenceState,
  intelligenceRecord
} from "../src/lib/session-intelligence";

describe("session-intelligence.ts", () => {
  describe("intelligenceRecord", () => {
    it("ควรคืนค่า object เดิมถ้าหากเป็น object", () => {
      const obj = { key: "value" };
      expect(intelligenceRecord(obj)).toEqual(obj);
    });

    it("ควรคืนค่า {} เสมอเมื่อไม่ใช่ object ที่ถูกต้อง (null, array, string)", () => {
      expect(intelligenceRecord(null)).toEqual({});
      expect(intelligenceRecord(["array"])).toEqual({});
      expect(intelligenceRecord("string")).toEqual({});
    });
  });

  describe("analystCommandText", () => {
    it("ควรดึงข้อความคำสั่งได้จาก key ต่างๆ ที่กำหนดไว้", () => {
      expect(analystCommandText({ command_text: "ls -la" })).toBe("ls -la");
      expect(analystCommandText({ input: "whoami" })).toBe("whoami");
    });

    it("ควรคืนค่า null หากเป็น [REDACTED]", () => {
      expect(analystCommandText("[REDACTED]")).toBeNull();
      expect(analystCommandText({ command: "[redacted]" })).toBeNull();
    });
  });

  describe("analystAttackerUsername", () => {
    it("ควรดึงชื่อผู้ใช้ได้เมื่อ visibility ตั้งเป็น AVAILABLE", () => {
      const record = { username_visibility: "AVAILABLE", attacker_username: "root" };
      expect(analystAttackerUsername(record)).toBe("root");
    });

    it("ควรคืนค่า null ถ้าระบบตั้งค่าไม่ให้แสดงผล หรือเป็น REDACTED", () => {
      const hiddenRecord = { username_visibility: "HIDDEN", attacker_username: "root" };
      expect(analystAttackerUsername(hiddenRecord)).toBeNull();

      const redactedRecord = { username_visibility: "AVAILABLE", attacker_username: "[REDACTED]" };
      expect(analystAttackerUsername(redactedRecord)).toBeNull();
    });
  });

  describe("selectedProviderFields", () => {
    it("ควรกรองเฉพาะข้อมูลจาก Provider ที่อยู่ใน SAFE_PROVIDER_CONTEXT_KEYS เท่านั้น", () => {
      const data = {
        country: "Thailand",
        isp: "True Internet",
        secret_internal_key: "should_not_show"
      };
      
      const fields = selectedProviderFields(data);
      // ควรกรอง secret_internal_key ทิ้งไป
      expect(fields).toEqual([
        ["country", "Thailand"],
        ["isp", "True Internet"]
      ]);
    });

    it("ควรแปลงค่า Array เป็น string ยาวไม่เกิน 12 item", () => {
      const data = {
        tags: ["malware", "botnet", "ssh"]
      };
      
      const fields = selectedProviderFields(data);
      expect(fields[0][1]).toBe("malware, botnet, ssh");
    });
  });

  describe("ensembleEvidenceState", () => {
    it("ควรตอบ AGREE หากโมเดลทั้งสองให้ผลลัพธ์เทคนิคตรงกัน", () => {
      const record = {
        s1_advisory: { predicted_technique: "T1110" },
        shadow_model: { technique_id: "T1110" }
      };
      expect(ensembleEvidenceState(record)).toBe("AGREE");
    });

    it("ควรตอบ DISAGREE หากผลลัพธ์ของโมเดลขัดแย้งกัน", () => {
      const record = {
        s1_advisory: { predicted_technique: "T1110" },
        shadow_model: { technique_id: "T1059" }
      };
      expect(ensembleEvidenceState(record)).toBe("DISAGREE");
    });

    it("ควรตอบ MODEL2_UNAVAILABLE หาก shadow model พัง", () => {
      const record = {
        s1_advisory: { predicted_technique: "T1110" },
        shadow_model: { status: "error" }
      };
      expect(ensembleEvidenceState(record)).toBe("MODEL2_UNAVAILABLE");
    });
  });
});
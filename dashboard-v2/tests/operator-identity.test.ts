import { describe, expect, it } from "vitest";
import { normalizeEmail, emailLookup } from "../src/lib/auth/operator-identity";

describe("operator-identity.ts", () => {
  describe("normalizeEmail", () => {
    it("ควรตัดช่องว่างและแปลงเป็นตัวพิมพ์เล็กให้ถูกต้อง", () => {
      expect(normalizeEmail("  Admin@EXAMPLE.com  ")).toBe("admin@example.com");
      expect(normalizeEmail("USER.name@Domain.CO.TH")).toBe("user.name@domain.co.th");
    });

    it("ควรคืนค่าอีเมลกลับมาหากรูปแบบถูกต้อง", () => {
      expect(normalizeEmail("admin@example.com")).toBe("admin@example.com");
      expect(normalizeEmail("first.last+tag@sub.example.org")).toBe("first.last+tag@sub.example.org");
    });

    it("ควรคืนค่า null หากรูปแบบอีเมลไม่ถูกต้อง", () => {
      expect(normalizeEmail("admin")).toBeNull();
      expect(normalizeEmail("admin@")).toBeNull();
      expect(normalizeEmail("admin@domain")).toBeNull(); // ขาด . 
      expect(normalizeEmail("@domain.com")).toBeNull();
      expect(normalizeEmail("admin @ domain.com")).toBeNull(); // มีช่องว่าง
    });
  });

  describe("emailLookup", () => {
    it("ควรสร้าง RegExp ที่ค้นหาแบบ Exact Match และไม่สนใจพิมพ์เล็กพิมพ์ใหญ่ (Case-insensitive)", () => {
      const regex = emailLookup("admin@example.com");
      
      // แมตช์พอดีคำ
      expect(regex.test("admin@example.com")).toBe(true);
      expect(regex.test("ADMIN@EXAMPLE.COM")).toBe(true);
      
      // ไม่แมตช์หากมีคำอื่นปนอยู่
      expect(regex.test("superadmin@example.com")).toBe(false);
      expect(regex.test("admin@example.com.th")).toBe(false);
    });

    it("ควร Escape อักขระพิเศษ (Regex Injection Protection) ได้อย่างถูกต้อง", () => {
      // อีเมลที่มีเครื่องหมาย + และ . ซึ่งใน Regex เป็นอักขระพิเศษ (Special Characters)
      const email = "user+tag.name@example.com";
      const regex = emailLookup(email);
      
      // แมตช์พอดีคำ
      expect(regex.test("user+tag.name@example.com")).toBe(true);
      
      // ต้องไม่แมตช์กับอีเมลที่เอาเครื่องหมาย . ไปแทนเป็นตัวอักษรใดๆ (พฤติกรรมดั้งเดิมของ Regex)
      expect(regex.test("user+tagXname@example.com")).toBe(false);
      
      // ต้องไม่แมตช์กับอีเมลที่ไม่มีเครื่องหมาย +
      expect(regex.test("usertag.name@example.com")).toBe(false);
    });
  });
});
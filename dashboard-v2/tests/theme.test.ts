import { describe, expect, it, vi, afterEach } from "vitest";
import { parseTheme, resolveTheme } from "../src/lib/theme";

describe("theme.ts", () => {
  describe("parseTheme", () => {
    it("ควรคืนค่า 'light' หรือ 'dark' หากตรงเงื่อนไข", () => {
      expect(parseTheme("light")).toBe("light");
      expect(parseTheme("dark")).toBe("dark");
    });

    it("ควร fallback เป็น 'system' สำหรับค่าอื่นๆ", () => {
      expect(parseTheme("invalid")).toBe("system");
      expect(parseTheme(null)).toBe("system");
      expect(parseTheme(undefined)).toBe("system");
    });
  });

  describe("resolveTheme", () => {
    const globalContext = globalThis as unknown as { window?: { matchMedia?: (query: string) => { matches: boolean } } };

    afterEach(() => {
      // ล้างค่า window ปลอมออกหลังจบการทดสอบแต่ละครั้ง เพื่อไม่ให้กระทบเทสต์อื่น
      delete globalContext.window;
    });

    it("ควรคืนค่าตาม preference โดยตรงหากไม่ใช่ 'system'", () => {
      expect(resolveTheme("light")).toBe("light");
      expect(resolveTheme("dark")).toBe("dark");
    });

    it("ควรคืนค่า 'dark' หากตั้งเป็น system และ OS ใช้โหมดมืด", () => {
      // จำลอง window object และ matchMedia สำหรับ Node.js
      globalContext.window = {
        matchMedia: vi.fn().mockImplementation((query: string) => ({
          matches: query === "(prefers-color-scheme: dark)",
        })),
      };

      expect(resolveTheme("system")).toBe("dark");
    });

    it("ควรคืนค่า 'light' หากตั้งเป็น system และ OS ไม่ได้ใช้โหมดมืด", () => {
      globalContext.window = {
        matchMedia: vi.fn().mockImplementation(() => ({
          matches: false,
        })),
      };

      expect(resolveTheme("system")).toBe("light");
    });

    it("ควรคืนค่า 'light' เป็น fallback หากไม่มี window (จำลองการทำงานบน Server/SSR)", () => {
      // ทำให้แน่ใจว่าไม่มี window อยู่จริงๆ
      delete globalContext.window;
      expect(resolveTheme("system")).toBe("light");
    });
  });
});
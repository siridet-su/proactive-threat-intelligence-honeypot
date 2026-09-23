import { describe, expect, it } from "vitest";
import { cn } from "../src/lib/utils";

describe("utils.ts - cn()", () => {
  it("ควรรวมคลาสปกติเข้าด้วยกันได้", () => {
    expect(cn("px-2", "py-1")).toBe("px-2 py-1");
  });

  it("ควรจัดการเงื่อนไข (Conditional) ได้ถูกต้อง", () => {
    const isActive = true;
    const isError = false;
    expect(cn("button", isActive && "bg-blue-500", isError && "bg-red-500")).toBe("button bg-blue-500");
  });

  it("ควรลบคลาสของ Tailwind ที่ขัดแย้งกัน โดยยึดคลาสหลังสุด", () => {
    // p-4 จะถูกทับด้วย p-2 เนื่องจากเป็นการกำหนด padding เหมือนกัน
    expect(cn("p-4 bg-red-500", "p-2")).toBe("bg-red-500 p-2");
  });

  it("ควรข้ามค่า null, undefined, หรือ false ได้โดยไม่ทำให้ผลลัพธ์พัง", () => {
    expect(cn("test", null, undefined, false, "passed")).toBe("test passed");
  });
});
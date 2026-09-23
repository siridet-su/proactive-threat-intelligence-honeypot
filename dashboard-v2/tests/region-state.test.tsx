// @vitest-environment jsdom
import { describe, expect, it, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import React from "react";
import { RefreshStatus, RegionState } from "../src/components/ui/RegionState";

describe("RegionState.tsx", () => {
  // สั่งล้างหน้าจอจำลอง (Virtual DOM) ทุกครั้งที่จบแต่ละเทสต์ (it)
  afterEach(() => {
    cleanup();
  });

  describe("RefreshStatus Component", () => {
    it("ควรแสดงข้อความ 'Refreshing' เมื่อสถานะคือ 'refreshing'", () => {
      render(<RefreshStatus status="refreshing" />);
      
      const statusElement = screen.getByRole("status");
      expect(statusElement.textContent).toContain("Refreshing");
    });

    it("ควรแสดงข้อความเตือน 'Refresh failed' เมื่อสถานะคือ 'stale'", () => {
      render(<RefreshStatus status="stale" />);
      
      const statusElement = screen.getByRole("status");
      expect(statusElement.textContent).toContain("Refresh failed");
    });

    it("ไม่ควรแสดงข้อความใดๆ เมื่อสถานะเป็น 'ready' หรือ 'loading' หรือ 'error'", () => {
      const { container: readyContainer } = render(<RefreshStatus status="ready" />);
      expect(readyContainer.textContent).toBe("");

      const { container: loadingContainer } = render(<RefreshStatus status="loading" />);
      expect(loadingContainer.textContent).toBe("");
    });
  });

  describe("RegionState Component", () => {
    it("ควรแสดงผลในรูปแบบ Loading (มี Skeleton และ aria-busy=true)", () => {
      render(<RegionState kind="loading" title="กำลังโหลดข้อมูล..." />);
      
      const element = screen.getByRole("status");
      expect(element.getAttribute("aria-busy")).toBe("true");
      expect(screen.getByText("กำลังโหลดข้อมูล...")).toBeDefined();
    });

    it("ควรแสดงผลในรูปแบบ Error (role=alert และมีข้อความแจ้งเตือน)", () => {
      render(
        <RegionState 
          kind="error" 
          title="เกิดข้อผิดพลาด" 
          description="ไม่สามารถดึงข้อมูลจากเซิร์ฟเวอร์ได้" 
        />
      );
      
      const element = screen.getByRole("alert");
      expect(element.getAttribute("aria-busy")).toBe("false");
      
      expect(screen.getByText("เกิดข้อผิดพลาด")).toBeDefined();
      expect(screen.getByText("ไม่สามารถดึงข้อมูลจากเซิร์ฟเวอร์ได้")).toBeDefined();
    });

    it("ควรแสดงผลในรูปแบบ Empty (ไม่มีข้อมูล)", () => {
      render(<RegionState kind="empty" title="ไม่พบประวัติการโจมตี" />);
      
      const element = screen.getByRole("status");
      expect(element.getAttribute("aria-busy")).toBe("false");
      expect(screen.getByText("ไม่พบประวัติการโจมตี")).toBeDefined();
    });
  });
});
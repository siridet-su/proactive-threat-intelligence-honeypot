// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import React from "react";
import DeploymentBadge from "../src/components/layout/DeploymentBadge";

describe("DeploymentBadge.tsx", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs(); // ล้างค่า Environment Variables ที่จำลองไว้ออกทุกครั้ง
  });

  it("ไม่ควรแสดงผลใดๆ หากไม่ได้อยู่ในโหมด STAGING", () => {
    // จำลองให้อยู่ในโหมด PRODUCTION
    vi.stubEnv("NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL", "PRODUCTION");
    
    const { container } = render(<DeploymentBadge />);
    expect(container.textContent).toBe(""); // ต้องไม่มีข้อความใดๆ เรนเดอร์ออกมา
  });

  it("ควรแสดงคำว่า STAGING หากตั้งค่าตัวแปรให้เป็น STAGING", () => {
    vi.stubEnv("NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL", "STAGING");
    
    render(<DeploymentBadge />);
    expect(screen.getByText("STAGING")).toBeDefined();
  });

  it("ควรแสดง Build ID และกรองอักขระที่ไม่ปลอดภัยออก", () => {
    vi.stubEnv("NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL", "STAGING");
    // ตัวอักษร '!' และ '@' ไม่ควรถูกนำมาแสดงผล
    vi.stubEnv("NEXT_PUBLIC_DASHBOARD_BUILD_ID", "v1.0.0-beta!@"); 
    
    render(<DeploymentBadge />);
    
    // ตรวจสอบว่าข้อความที่แสดงมีการกรองตัวอักษรพิเศษออกแล้ว
    const element = screen.getByText("STAGING v1.0.0-beta");
    expect(element).toBeDefined();
    
    // ตรวจสอบ aria-label ว่าทำงานถูกต้อง
    const badge = screen.getByLabelText("Staging build v1.0.0-beta");
    expect(badge).toBeDefined();
  });
  
  it("ควรจำกัดความยาวของ Build ID ไว้ที่ไม่เกิน 12 ตัวอักษร", () => {
    vi.stubEnv("NEXT_PUBLIC_DASHBOARD_DEPLOYMENT_LABEL", "STAGING");
    // ตัวอักษรยาว 20 ตัว
    vi.stubEnv("NEXT_PUBLIC_DASHBOARD_BUILD_ID", "12345678901234567890"); 
    
    render(<DeploymentBadge />);
    
    // ควรถูกตัดเหลือแค่ 12 ตัวแรก
    expect(screen.getByText("STAGING 123456789012")).toBeDefined();
  });
});
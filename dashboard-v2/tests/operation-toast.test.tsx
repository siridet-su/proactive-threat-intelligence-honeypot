// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import React from "react";
import { OperationToast } from "../src/components/ui/OperationToast";

describe("OperationToast.tsx", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  const defaultProps = {
    title: "บันทึกสำเร็จ",
    description: "ข้อมูลของคุณถูกบันทึกเรียบร้อยแล้ว",
    onDismiss: vi.fn(),
  };

  it("ควรแสดงผลแบบ Success ได้อย่างถูกต้อง (role=status, aria-live=polite)", () => {
    render(<OperationToast kind="success" {...defaultProps} />);

    // ตรวจสอบข้อความ
    expect(screen.getByText("บันทึกสำเร็จ")).toBeDefined();
    expect(screen.getByText("ข้อมูลของคุณถูกบันทึกเรียบร้อยแล้ว")).toBeDefined();

    // ตรวจสอบ Accessibility สำหรับข้อความแบบ Success
    const toastElement = screen.getByRole("status");
    expect(toastElement.getAttribute("aria-live")).toBe("polite");
  });

  it("ควรแสดงผลแบบ Error ได้อย่างถูกต้อง (role=alert, aria-live=assertive)", () => {
    render(
      <OperationToast 
        kind="error" 
        title="เกิดข้อผิดพลาด" 
        description="ไม่สามารถลบข้อมูลได้" 
        onDismiss={defaultProps.onDismiss} 
      />
    );

    // ตรวจสอบข้อความ
    expect(screen.getByText("เกิดข้อผิดพลาด")).toBeDefined();
    expect(screen.getByText("ไม่สามารถลบข้อมูลได้")).toBeDefined();

    // ตรวจสอบ Accessibility สำหรับข้อความแบบ Error
    const toastElement = screen.getByRole("alert");
    expect(toastElement.getAttribute("aria-live")).toBe("assertive");
  });

  it("เมื่อกดปุ่มกากบาท ควรเรียกใช้งานฟังก์ชัน onDismiss", () => {
    render(<OperationToast kind="success" {...defaultProps} />);

    // ค้นหาปุ่มปิดจาก aria-label
    const dismissButton = screen.getByRole("button", { name: "Dismiss notification" });
    fireEvent.click(dismissButton);

    // ตรวจสอบว่าฟังก์ชัน onDismiss ถูกเรียก 1 ครั้ง
    expect(defaultProps.onDismiss).toHaveBeenCalledTimes(1);
  });
});
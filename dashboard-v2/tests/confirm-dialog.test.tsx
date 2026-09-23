// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import React from "react";
import { ConfirmDialog } from "../src/components/ui/ConfirmDialog";

describe("ConfirmDialog.tsx", () => {
  // ล้างหน้าจอจำลองทุกครั้งที่จบเทสต์
  afterEach(() => {
    cleanup();
    vi.clearAllMocks(); // ล้างข้อมูลการจำลองฟังก์ชันด้วย
  });

  const defaultProps = {
    open: true,
    onOpenChange: vi.fn(),
    onConfirm: vi.fn(),
    title: "ยืนยันการทำรายการ",
    description: "คุณแน่ใจหรือไม่ที่จะลบข้อมูลนี้?",
    confirmLabel: "ยืนยัน",
  };

  it("ควรแสดงผลข้อความ หัวข้อ และปุ่มต่างๆ ได้ถูกต้อง", () => {
    render(<ConfirmDialog {...defaultProps} />);

    expect(screen.getByText("ยืนยันการทำรายการ")).toBeDefined();
    expect(screen.getByText("คุณแน่ใจหรือไม่ที่จะลบข้อมูลนี้?")).toBeDefined();
    
    // ควรมีปุ่ม Cancel และปุ่ม "ยืนยัน"
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDefined();
    expect(screen.getByRole("button", { name: "ยืนยัน" })).toBeDefined();
  });

  it("เมื่อกดปุ่ม ยืนยัน ควรเรียกใช้งานฟังก์ชัน onConfirm", () => {
    render(<ConfirmDialog {...defaultProps} />);

    const confirmButton = screen.getByRole("button", { name: "ยืนยัน" });
    fireEvent.click(confirmButton); // จำลองการคลิกปุ่ม

    // ตรวจสอบว่าฟังก์ชัน onConfirm ถูกเรียก 1 ครั้ง
    expect(defaultProps.onConfirm).toHaveBeenCalledTimes(1);
  });

  it("เมื่อกดปุ่ม Cancel ควรเรียกใช้งานฟังก์ชัน onOpenChange", () => {
    render(<ConfirmDialog {...defaultProps} />);

    const cancelButton = screen.getByRole("button", { name: "Cancel" });
    fireEvent.click(cancelButton);

    // ตรวจสอบว่าฟังก์ชัน onOpenChange ถูกเรียกเพื่อขอปิด Dialog (ส่งค่า false)
    expect(defaultProps.onOpenChange).toHaveBeenCalledWith(false);
  });

  it("เมื่อสถานะ isProcessing=true ควรแสดงไอคอนโหลดและปุ่มต้องกดไม่ได้ (disabled)", () => {
    render(
      <ConfirmDialog 
        {...defaultProps} 
        isProcessing={true} 
        processingLabel="กำลังลบ..." 
      />
    );

    // ปุ่ม Cancel ต้องกดไม่ได้
    const cancelButton = screen.getByRole("button", { name: "Cancel" }) as HTMLButtonElement;
    expect(cancelButton.disabled).toBe(true);

    // ปุ่ม Confirm จะถูกเปลี่ยนข้อความตาม processingLabel และต้องกดไม่ได้
    const confirmButton = screen.getByRole("button", { name: "กำลังลบ..." }) as HTMLButtonElement;
    expect(confirmButton.disabled).toBe(true);
    
    // ลองคลิกดู ต้องไม่มีผล
    fireEvent.click(confirmButton);
    expect(defaultProps.onConfirm).not.toHaveBeenCalled();
  });

  it("ควรแสดงกล่องข้อความ Error (role=alert) หากระบุ errorMessage", () => {
    render(
      <ConfirmDialog 
        {...defaultProps} 
        errorMessage="ไม่สามารถเชื่อมต่อฐานข้อมูลได้" 
      />
    );

    const alertMessage = screen.getByRole("alert");
    expect(alertMessage.textContent).toBe("ไม่สามารถเชื่อมต่อฐานข้อมูลได้");
  });

  it("ไม่ควรแสดงอะไรเลย หาก open=false", () => {
    render(<ConfirmDialog {...defaultProps} open={false} />);
    
    // Radix UI จะไม่เรนเดอร์เนื้อหาเข้า DOM หากไม่ได้เปิดอยู่
    expect(screen.queryByText("ยืนยันการทำรายการ")).toBeNull();
  });
});
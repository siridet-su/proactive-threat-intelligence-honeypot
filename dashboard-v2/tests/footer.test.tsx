// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import React from "react";
import Footer from "../src/components/layout/Footer";

// จำลอง (Mock) Component ของ Next.js เพื่อไม่ให้ระบบต้องโหลด Router จริง
vi.mock("next/link", () => ({
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

// จำลอง SessionAwareLink เพื่อตัดความซับซ้อนเรื่องการเช็ค Session ออกไปจากการเทสต์ Layout
vi.mock("@/components/auth/SessionAwareLink", () => ({
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href} data-testid="session-aware-link">{children}</a>
  ),
}));

describe("Footer.tsx", () => {
  afterEach(() => {
    cleanup();
  });

  it("ควรแสดงชื่อโปรเจกต์และคำอธิบายได้อย่างถูกต้อง", () => {
    render(<Footer />);
    
    expect(screen.getByText("PTI-Honeypot")).toBeDefined();
    expect(screen.getByText("Read-only threat intelligence for authorized operators.")).toBeDefined();
  });

  it("ควรมีเมนูนำทาง (Navigation) พร้อมลิงก์ที่ถูกต้อง", () => {
    render(<Footer />);
    
    // ตรวจสอบโครงสร้าง Accessibility (a11y) ว่าเป็นแถบเมนู (nav) จริงๆ
    const nav = screen.getByRole("navigation", { name: "Footer navigation" });
    expect(nav).toBeDefined();

    // ตรวจสอบลิงก์ Overview (จำลองจาก next/link)
    const overviewLink = screen.getByRole("link", { name: "Overview" });
    expect(overviewLink.getAttribute("href")).toBe("#overview");

    // ตรวจสอบลิงก์ Documentation (จำลองจาก SessionAwareLink ผ่าน data-testid)
    const docLink = screen.getByTestId("session-aware-link");
    expect(docLink.textContent).toBe("Documentation");
    expect(docLink.getAttribute("href")).toBe("#documentation");

    // ตรวจสอบลิงก์ Operator sign in
    const loginLink = screen.getByRole("link", { name: "Operator sign in" });
    expect(loginLink.getAttribute("href")).toBe("/login");
  });
});
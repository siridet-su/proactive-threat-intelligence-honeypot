// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import React from "react";
import Navbar from "../src/components/layout/Navbar";

// จำลอง Next.js Router
const mockReplace = vi.fn();
const mockRefresh = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    replace: mockReplace,
    refresh: mockRefresh,
  }),
}));

// จำลอง Next.js Link
vi.mock("next/link", () => ({
  default: ({ children, href, onClick, role, className }: { children: React.ReactNode; href: string; onClick?: () => void; role?: string; className?: string }) => (
    <a href={href} onClick={onClick} role={role} className={className}>{children}</a>
  ),
}));

// จำลอง SessionAwareLink
vi.mock("@/components/auth/SessionAwareLink", () => ({
  default: ({ children, href, onClick }: { children: React.ReactNode; href: string; onClick?: () => void }) => (
    <a href={href} onClick={onClick} data-testid="session-aware-link">{children}</a>
  ),
}));

// จำลอง ThemeToggle
vi.mock("@/components/theme/ThemeToggle", () => ({
  default: () => <button data-testid="theme-toggle">Theme Toggle</button>,
}));

describe("Navbar.tsx", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("ควรแสดงปุ่ม Sign in หากยังไม่ได้เข้าสู่ระบบ (Guest Mode)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
    }));

    render(<Navbar />);

    await waitFor(() => {
      // ใช้ getAllByText แล้วเลือกตัวแรก ป้องกันปัญหาเจอซ้ำระหว่าง Desktop กับ Mobile
      const signinButtons = screen.getAllByText("Sign in");
      expect(signinButtons.length).toBeGreaterThan(0);
    });
  });

  it("ควรแสดงข้อมูลชื่อ Operator และปุ่มเปิดเมนูโปรไฟล์เมื่อเข้าสู่ระบบแล้ว", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        operatorId: "admin_01",
        role: "Admin",
        fullName: "System Security Admin",
      }),
    }));

    render(<Navbar />);

    await waitFor(() => {
      const profileButton = screen.getByRole("button", { name: /Open profile menu for System Security Admin/i });
      expect(profileButton).toBeDefined();
    });

    // ทดสอบคลิกเปิดเมนูโปรไฟล์
    const profileButton = screen.getByRole("button", { name: /Open profile menu for System Security Admin/i });
    fireEvent.click(profileButton);

    // ตรวจสอบผ่าน role="menuitem" เพื่อความเจาะจง
    expect(screen.getByRole("menuitem", { name: /View profile/i })).toBeDefined();
    expect(screen.getByRole("menuitem", { name: /Open operator console/i })).toBeDefined();
    expect(screen.getByRole("menuitem", { name: /Sign out/i })).toBeDefined();
  });

  it("เมื่อกด Sign out ควรเปิด Dialog ยืนยัน และเมื่อยืนยันควรเรียก API ออกจากระบบและเปลี่ยนหน้า", async () => {
    const fetchMock = vi.fn().mockImplementation((url) => {
      if (url === "/api/auth/session") {
        return Promise.resolve({
          ok: true,
          json: async () => ({ operatorId: "admin", role: "Admin", fullName: "Admin" }),
        });
      }
      if (url === "/api/auth/logout") {
        return Promise.resolve({ ok: true });
      }
      return Promise.reject(new Error("unknown api"));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<Navbar />);

    await waitFor(() => {
      const profileButton = screen.getByRole("button", { name: /Open profile menu for Admin/i });
      expect(profileButton).toBeDefined();
    });

    // เปิดเมนูโปรไฟล์
    const profileButton = screen.getByRole("button", { name: /Open profile menu for Admin/i });
    fireEvent.click(profileButton);

    // กดปุ่ม Sign out ในเมนู
    const signOutMenuItem = screen.getByRole("menuitem", { name: /Sign out/i });
    fireEvent.click(signOutMenuItem);

    // Dialog ยืนยันการออกจากระบบควรปรากฏขึ้น
    expect(screen.getByText("Sign out of PTI-Honeypot?")).toBeDefined();

    // กดปุ่มยืนยัน "Sign out" ใน Dialog
    const confirmButton = screen.getByRole("button", { name: /^Sign out$/ });
    fireEvent.click(confirmButton);

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith("/api/auth/logout", { method: "POST" });
      expect(mockReplace).toHaveBeenCalledWith("/");
      expect(mockRefresh).toHaveBeenCalled();
    });
  });
});
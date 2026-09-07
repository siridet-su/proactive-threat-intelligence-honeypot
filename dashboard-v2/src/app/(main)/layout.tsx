"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Users, ShieldCheck, LayoutDashboard, Brain, Clock, LogOut, ArrowLeft, Bug, User, Settings, Activity, Archive, Home, Menu, X } from "lucide-react";
import { useEffect, useState, useRef } from "react";

import ThemeToggle from "@/components/theme/ThemeToggle";
import { ThreatFeedProvider } from "@/components/threat/ThreatFeedProvider";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const drawer = useRef<HTMLDialogElement>(null);
  const navigationTrigger = useRef<HTMLButtonElement>(null);
  const [navigationOpen, setNavigationOpen] = useState(false);
  const [logoutConfirmationOpen, setLogoutConfirmationOpen] = useState(false);
  const closeNavigation = () => { drawer.current?.close(); setNavigationOpen(false); };
  useEffect(() => {
    const desktop = window.matchMedia("(min-width: 1024px)");
    const onResize = () => { if (desktop.matches) closeNavigation(); };
    desktop.addEventListener("change", onResize);
    return () => desktop.removeEventListener("change", onResize);
  }, []);
  const pathname = usePathname();
  const router = useRouter();

  const [time, setTime] = useState("");
  const [userRole, setUserRole] = useState("");
  const [operatorId, setOperatorId] = useState("");
  const [userName, setUserName] = useState(""); // State สำหรับเก็บชื่อหน้า

  useEffect(() => {
    let cancelled = false;
    const loadSession = async () => {
      try {
        const response = await fetch("/api/auth/session", { cache: "no-store" });
        if (!response.ok) throw new Error("Session unavailable");
        const data: unknown = await response.json();
        if (!data || typeof data !== "object") throw new Error("Session unavailable");
        const session = data as { operatorId?: unknown; role?: unknown; fullName?: unknown };
        if (typeof session.operatorId !== "string" || typeof session.role !== "string") throw new Error("Session unavailable");
        if (cancelled) return;
        setOperatorId(session.operatorId);
        setUserRole(session.role);
        setUserName(typeof session.fullName === "string" ? session.fullName.split(" ")[0] : session.operatorId);
      } catch {
        if (!cancelled) router.replace("/login");
      }
    };
    void loadSession();

    const timer = setInterval(() => {
      setTime(new Date().toLocaleTimeString('en-US', { hour12: false }));
    }, 1000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [router]);

  const handleLogout = () => {
    setLogoutConfirmationOpen(true);
  };

  const confirmLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } finally {
      router.push("/");
      router.refresh();
    }
  };

  const handleBack = () => {
    router.back();
  };

  const getPageTitle = () => {
    if (pathname.includes('/profile')) return 'User Profile';
    if (pathname.includes('/system-health')) return 'System Health';
    if (pathname.includes('/malware-vault')) return 'Malware Vault';
    if (pathname.includes('/user-management')) return 'User Management';
    if (pathname.includes('/archives')) return 'Security Archive';
    if (pathname.includes('/threat-intel/')) return 'Hacker Profile Analysis';
    if (pathname.includes('/threat-intel')) return 'Threat Intelligence';
    return 'System Overview';
  };

  const navigation = (
    <>
      <nav aria-label="Main navigation" className="flex-1 space-y-1 overflow-y-auto px-4 py-6">
        <div className="mb-5 border-b border-border pb-4">
          <Link href="/" className="ui-nav-link" onClick={closeNavigation} aria-label="Open PTI-Honeypot landing page">
            <Home className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
            <span>Landing page</span>
          </Link>
        </div>
        <p className="mb-4 px-3 text-xs font-medium text-text-subtle">Vigilance Protocol</p>
        {[
          { href: "/dashboard", title: "Dashboard", icon: LayoutDashboard, active: pathname === "/dashboard" },
          { href: "/threat-intel", title: "Threat Intel", icon: Brain, active: pathname.includes("/threat-intel") },
          { href: "/archives", title: "Archives", icon: Archive, active: pathname.includes("/archives") },
          { href: "/malware-vault", title: "Malware Vault", icon: Bug, active: pathname.includes("/malware-vault") },
          { href: "/system-health", title: "System Health", icon: Activity, active: pathname.includes("/system-health") },
          ...((userRole === "Admin" || userRole === "admin") ? [{ href: "/user-management", title: "User Management", icon: Users, active: pathname.includes("/user-management") }] : []),
        ].map(({ href, title, icon: Icon, active }) => (
          <Link key={href} href={href} className="ui-nav-link" aria-current={active ? "page" : undefined} onClick={closeNavigation}>
            <Icon className="h-[18px] w-[18px] shrink-0" aria-hidden="true" /><span>{title}</span>
          </Link>
        ))}
      </nav>
      <div className="space-y-3 border-t border-border p-4">
        <Link href="/profile" onClick={closeNavigation} aria-current={pathname.includes("/profile") ? "page" : undefined} className="ui-nav-link border border-border bg-surface-subtle">
          <User className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <p className="break-words font-semibold text-text">{userName || operatorId || "Operator"}</p>
            <p className="text-xs text-text-subtle">{userRole === "Admin" ? "LVL-4 ACCESS" : "LVL-2 ACCESS"}</p>
          </div>
          <Settings className="h-4 w-4 shrink-0" aria-hidden="true" />
        </Link>
        <button onClick={handleLogout} className="ui-button w-full"><LogOut className="h-4 w-4" aria-hidden="true" />Logout</button>
      </div>
    </>
  );

  return (
    <ThreatFeedProvider>
    <div className="min-h-dvh bg-canvas text-text">
      <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[120] focus:rounded-lg focus:bg-surface focus:p-3">Skip to content</a>
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-border bg-surface lg:flex">
        <div className="flex h-16 shrink-0 items-center gap-3 border-b border-border px-6">
          <ShieldCheck className="h-6 w-6 text-primary" aria-hidden="true" />
          <span className="text-base font-semibold">PTI-Honeypot</span>
        </div>
        {navigation}
      </aside>
      <dialog ref={drawer} className="ui-drawer" aria-label="Navigation" onClose={() => { setNavigationOpen(false); if (!window.matchMedia("(min-width: 1024px)").matches) navigationTrigger.current?.focus(); }} onClick={event => { if (event.target === event.currentTarget && event.clientX > event.currentTarget.getBoundingClientRect().right) closeNavigation(); }}>
        <div className="flex h-full flex-col">
          <div className="flex h-16 shrink-0 items-center justify-between border-b border-border px-4">
            <span className="flex items-center gap-2 font-semibold"><ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />PTI-Honeypot</span>
            <button className="ui-button" onClick={closeNavigation} aria-label="Close navigation"><X className="h-4 w-4" /></button>
          </div>
          {navigation}
        </div>
      </dialog>
      <div className="min-w-0 lg:ml-60">
        <header className="sticky top-0 z-20 border-b border-border bg-surface">
          <div className="flex min-h-16 items-center justify-between gap-3 px-4 lg:px-8">
            <div className="flex min-w-0 items-center gap-2 sm:gap-3">
              <button ref={navigationTrigger} className="ui-button px-2 lg:hidden" aria-label="Open navigation" aria-haspopup="dialog" aria-expanded={navigationOpen} onClick={() => { drawer.current?.showModal(); setNavigationOpen(true); }}><Menu className="h-4 w-4" /></button>
              {pathname !== "/dashboard" && <button onClick={handleBack} className="ui-button px-2" title="Go back" aria-label="Go back"><ArrowLeft className="h-4 w-4" /></button>}
              <span className="text-xs font-medium sm:text-sm">{getPageTitle()}</span>
            </div>
            <div className="flex items-center gap-6">
              <div className="hidden items-center gap-2 text-xs text-text-muted sm:flex"><Clock className="h-4 w-4" aria-hidden="true" /><span>Local time</span><time aria-label="Current local time" className="font-mono tabular-nums">{time || "00:00:00"}</time></div>
              <ThemeToggle />
            </div>
          </div>
        </header>
        <main id="main-content" tabIndex={-1} className="mx-auto w-full max-w-[1440px] p-4 md:p-6 lg:p-8">{children}</main>
      </div>
      <ConfirmDialog open={logoutConfirmationOpen} onOpenChange={setLogoutConfirmationOpen} onConfirm={() => void confirmLogout()} title="Sign out of PTI-Honeypot?" description="Your current dashboard session will end and you will return to the sign-in screen." confirmLabel="Sign out" />
    </div>
    </ThreatFeedProvider>
  );
}

"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, ChevronDown, UserRound } from "lucide-react";

import ThemeToggle from "@/components/theme/ThemeToggle";
import { cn } from "@/lib/utils";

const topics = [
  { id: "overview", href: "#overview", label: "Overview" },
  { id: "capabilities", href: "#capabilities", label: "Capabilities" },
  { id: "how-it-works", href: "#how-it-works", label: "How it works" },
  { id: "documentation", href: "#documentation", label: "Documentation" },
] as const;

type TopicId = (typeof topics)[number]["id"];
type OpenMenu = "theme" | "account" | "mobile" | null;

type PublicSession = {
  operatorId: string;
  role: string;
  fullName: string;
};

function getTopicFromHash(): TopicId | null {
  const topic = window.location.hash.slice(1);
  return topics.some(({ id }) => id === topic) ? topic as TopicId : null;
}

function topicLinkClass(active: boolean) {
  return cn(
    "group relative rounded-lg border px-3 py-2 transition-colors duration-150",
    active
      ? "border-primary-border bg-primary-subtle text-primary"
      : "border-transparent text-text-muted hover:border-border hover:bg-surface-hover hover:text-text",
  );
}

function getAccountName(session: PublicSession) {
  return session.fullName.trim() || session.operatorId;
}

export default function Navbar() {
  const [activeTopic, setActiveTopic] = useState<TopicId>("overview");
  const [session, setSession] = useState<PublicSession | null>(null);
  const [openMenu, setOpenMenu] = useState<OpenMenu>(null);
  const navbar = useRef<HTMLElement>(null);

  useEffect(() => {
    const controller = new AbortController();

    const loadSession = async () => {
      try {
        const response = await fetch("/api/auth/session", {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) return;

        const data: unknown = await response.json();
        if (!data || typeof data !== "object" || Array.isArray(data)) return;

        const candidate = data as Record<string, unknown>;
        if (typeof candidate.operatorId !== "string" || typeof candidate.role !== "string") return;
        if (controller.signal.aborted) return;

        setSession({
          operatorId: candidate.operatorId,
          role: candidate.role,
          fullName: typeof candidate.fullName === "string" ? candidate.fullName : "",
        });
      } catch {
        if (!controller.signal.aborted) setSession(null);
      }
    };

    void loadSession();
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const sections = topics
      .map(({ id }) => document.getElementById(id))
      .filter((section): section is HTMLElement => Boolean(section));
    let frame = 0;

    const updateActiveTopic = () => {
      if (frame) return;
      frame = window.requestAnimationFrame(() => {
        frame = 0;
        if (window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2) {
          setActiveTopic(topics[topics.length - 1].id);
          return;
        }
        const marker = window.innerWidth < 640 ? 112 : 132;
        let currentTopic: TopicId = "overview";
        for (const section of sections) {
          if (section.getBoundingClientRect().top <= marker) currentTopic = section.id as TopicId;
          else break;
        }
        setActiveTopic(currentTopic);
      });
    };

    const hashTopic = getTopicFromHash();
    const hashTimer = hashTopic ? window.setTimeout(() => setActiveTopic(hashTopic), 0) : undefined;
    const handleHashChange = () => {
      const nextTopic = getTopicFromHash();
      if (nextTopic) setActiveTopic(nextTopic);
      updateActiveTopic();
    };
    updateActiveTopic();
    window.addEventListener("scroll", updateActiveTopic, { passive: true });
    window.addEventListener("resize", updateActiveTopic);
    window.addEventListener("hashchange", handleHashChange);

    return () => {
      if (hashTimer) window.clearTimeout(hashTimer);
      if (frame) window.cancelAnimationFrame(frame);
      window.removeEventListener("scroll", updateActiveTopic);
      window.removeEventListener("resize", updateActiveTopic);
      window.removeEventListener("hashchange", handleHashChange);
    };
  }, []);

  useEffect(() => {
    const closeOnOutsidePointer = (event: PointerEvent) => {
      if (event.target instanceof Node && !navbar.current?.contains(event.target)) setOpenMenu(null);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpenMenu(null);
    };

    document.addEventListener("pointerdown", closeOnOutsidePointer);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  const handleTopicClick = (topic: TopicId) => {
    setActiveTopic(topic);
    setOpenMenu(null);
  };

  const closeMenus = () => {
    setOpenMenu(null);
  };

  const accountName = session ? getAccountName(session) : "";
  const accountInitial = accountName.charAt(0).toUpperCase() || "O";

  return (
    <header ref={navbar} className="sticky top-0 z-40 border-b border-border bg-surface shadow-[var(--shadow-card)]">
      <nav aria-label="Public navigation" className="mx-auto flex min-h-16 w-full max-w-7xl items-center justify-between gap-4 px-5 py-3 sm:px-8">
        <Link href="/" className="flex items-center gap-3 text-base font-semibold tracking-tight text-text">
          <span className="grid h-8 w-8 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary" aria-hidden="true">P</span>
          PTI-Honeypot
        </Link>

        <div className="hidden items-center gap-1 text-sm font-medium text-text-muted md:flex">
          {topics.map((topic) => {
            const active = activeTopic === topic.id;
            return (
              <Link
                key={topic.id}
                href={topic.href}
                className={topicLinkClass(active)}
                aria-current={active ? "location" : undefined}
                aria-label={`${topic.label}${active ? " (current topic)" : ""}`}
                onClick={() => handleTopicClick(topic.id)}
              >
                {topic.label}
                <span aria-hidden="true" className={cn("absolute inset-x-3 bottom-1 h-0.5 rounded-full transition-colors duration-150", active ? "bg-primary" : "bg-transparent group-hover:bg-border-strong")} />
                {active && <span className="sr-only">Current topic</span>}
              </Link>
            );
          })}
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <ThemeToggle open={openMenu === "theme"} onOpenChange={(open) => setOpenMenu(open ? "theme" : null)} />
          {session ? (
            <details open={openMenu === "account"} className="relative hidden md:block">
              <summary
                className="ui-button list-none gap-2 px-2.5 [&::-webkit-details-marker]:hidden"
                aria-haspopup="menu"
                aria-label={`Open profile menu for ${accountName}`}
                onClick={(event) => {
                  event.preventDefault();
                  setOpenMenu((menu) => menu === "account" ? null : "account");
                }}
              >
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded-md border border-primary-border bg-primary-subtle text-xs font-semibold text-primary" aria-hidden="true">
                  {accountInitial}
                </span>
                <span className="hidden min-w-0 max-w-28 text-left lg:block">
                  <span className="block truncate text-xs font-semibold leading-4 text-text">{accountName}</span>
                  <span className="block truncate text-xs leading-4 text-text-subtle">{session.role}</span>
                </span>
                <ChevronDown className="h-4 w-4 shrink-0 text-text-subtle" aria-hidden="true" />
              </summary>
              <div className="absolute right-0 top-[calc(100%+8px)] z-50 w-56 rounded-xl border border-border bg-surface-raised p-2 shadow-[var(--shadow-raised)]" role="menu" aria-label="Profile menu">
                <div className="rounded-lg bg-surface-subtle p-3">
                  <div className="flex items-center gap-3">
                    <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-sm font-semibold text-primary" aria-hidden="true">
                      {accountInitial}
                    </span>
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-text">{accountName}</p>
                      <p className="mt-0.5 text-xs text-text-muted">{session.role} operator</p>
                    </div>
                  </div>
                  <p className="mt-3 border-t border-border pt-2 text-xs text-text-subtle">Operator ID <span className="ml-1 font-mono text-text">{session.operatorId}</span></p>
                </div>
                <div className="mt-1 grid gap-1">
                  <Link href="/profile" role="menuitem" className="flex min-h-10 items-center gap-2 rounded-lg px-3 text-sm font-medium text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text" onClick={closeMenus}>
                    <UserRound className="h-4 w-4 text-primary" aria-hidden="true" />View profile
                  </Link>
                  <Link href="/dashboard" role="menuitem" className="flex min-h-10 items-center justify-between gap-2 rounded-lg px-3 text-sm font-medium text-text-muted transition-colors duration-150 hover:bg-surface-hover hover:text-text" onClick={closeMenus}>
                    <span className="inline-flex items-center gap-2"><ArrowUpRight className="h-4 w-4 text-primary" aria-hidden="true" />Open operator console</span>
                    <ArrowUpRight className="h-3.5 w-3.5 text-text-subtle" aria-hidden="true" />
                  </Link>
                </div>
              </div>
            </details>
          ) : (
            <Link href="/login" className="ui-button ui-button-primary hidden px-5 sm:inline-flex">Sign in</Link>
          )}
          <details open={openMenu === "mobile"} className="relative md:hidden">
            <summary className="ui-button list-none px-3 [&::-webkit-details-marker]:hidden" onClick={(event) => {
              event.preventDefault();
              setOpenMenu((menu) => menu === "mobile" ? null : "mobile");
            }}>Menu</summary>
            <div className="absolute right-0 top-[calc(100%+8px)] z-50 min-w-56 rounded-xl border border-border bg-surface p-2 shadow-[var(--shadow-raised)]">
              <div className="flex flex-col gap-1 text-sm font-medium text-text-muted">
                {topics.map((topic) => {
                  const active = activeTopic === topic.id;
                  return (
                    <Link
                      key={topic.id}
                      href={topic.href}
                      className={cn("flex items-center justify-between gap-3 rounded-lg border px-3 py-2.5 transition-colors duration-150", active ? "border-primary-border bg-primary-subtle text-primary" : "border-transparent hover:border-border hover:bg-surface-hover hover:text-text")}
                      aria-current={active ? "location" : undefined}
                      aria-label={`${topic.label}${active ? " (current topic)" : ""}`}
                      onClick={() => handleTopicClick(topic.id)}
                    >
                      <span>{topic.label}</span>
                      {active && <span className="ui-badge border-primary-border bg-surface text-primary">Current</span>}
                    </Link>
                  );
                })}
                {session ? (
                  <>
                    <div className="mx-1 mt-1 rounded-lg border border-border bg-surface-subtle p-3">
                      <div className="flex items-center gap-3">
                        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-sm font-semibold text-primary" aria-hidden="true">
                          {accountInitial}
                        </span>
                        <div className="min-w-0">
                          <p className="truncate text-sm font-semibold text-text">{accountName}</p>
                          <p className="text-xs text-text-muted">{session.role}</p>
                        </div>
                      </div>
                      <p className="mt-2 break-all font-mono text-xs text-text-subtle">{session.operatorId}</p>
                    </div>
                    <Link href="/dashboard" className="ui-button ui-button-primary mt-1 w-full justify-between" onClick={closeMenus}>
                      <span>Open operator console</span>
                      <ArrowUpRight className="h-4 w-4" aria-hidden="true" />
                    </Link>
                    <Link href="/profile" className="ui-button w-full justify-start" onClick={closeMenus}>
                      <UserRound className="h-4 w-4" aria-hidden="true" />
                      View profile
                    </Link>
                  </>
                ) : (
                  <Link href="/login" className="ui-button ui-button-primary mt-1 w-full" onClick={closeMenus}>Sign in</Link>
                )}
              </div>
            </div>
          </details>
        </div>
      </nav>
    </header>
  );
}

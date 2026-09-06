"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";

import ThemeToggle from "@/components/theme/ThemeToggle";
import { cn } from "@/lib/utils";

const topics = [
  { id: "overview", href: "#overview", label: "Overview" },
  { id: "capabilities", href: "#capabilities", label: "Capabilities" },
  { id: "how-it-works", href: "#how-it-works", label: "How it works" },
  { id: "documentation", href: "#documentation", label: "Documentation" },
] as const;

type TopicId = (typeof topics)[number]["id"];

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

export default function Navbar() {
  const [activeTopic, setActiveTopic] = useState<TopicId>("overview");
  const mobileMenu = useRef<HTMLDetailsElement>(null);

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

  const handleTopicClick = (topic: TopicId) => {
    setActiveTopic(topic);
    mobileMenu.current?.removeAttribute("open");
  };

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-surface shadow-[var(--shadow-card)]">
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
          <ThemeToggle />
          <Link href="/login" className="ui-button ui-button-primary hidden px-5 sm:inline-flex">Sign in</Link>
          <details ref={mobileMenu} className="relative md:hidden">
            <summary className="ui-button list-none px-3 [&::-webkit-details-marker]:hidden">Menu</summary>
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
                <Link href="/login" className="ui-button ui-button-primary mt-1 w-full">Sign in</Link>
              </div>
            </div>
          </details>
        </div>
      </nav>
    </header>
  );
}

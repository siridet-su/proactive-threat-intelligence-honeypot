"use client";

import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";

import { cn } from "@/lib/utils";

interface ScrollRevealProps {
  children: ReactNode;
  className?: string;
  delay?: number;
}

export default function ScrollReveal({ children, className, delay = 0 }: ScrollRevealProps) {
  const element = useRef<HTMLDivElement>(null);
  const [isVisible, setIsVisible] = useState<boolean | null>(null);

  useEffect(() => {
    const node = element.current;
    if (!node) return;

    let observer: IntersectionObserver | null = null;
    const frame = window.requestAnimationFrame(() => {
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) {
        setIsVisible(true);
        return;
      }

      if (node.getBoundingClientRect().top < window.innerHeight * 0.94) {
        setIsVisible(true);
        return;
      }

      setIsVisible(false);
      observer = new IntersectionObserver(([entry]) => {
        if (!entry?.isIntersecting) return;
        setIsVisible(true);
        observer?.disconnect();
      }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" });
      observer.observe(node);
    });

    return () => {
      window.cancelAnimationFrame(frame);
      observer?.disconnect();
    };
  }, []);

  return (
    <div
      ref={element}
      className={cn("ui-scroll-reveal", isVisible === false ? "ui-scroll-reveal-hidden" : "ui-scroll-reveal-visible", className)}
      style={{ "--scroll-reveal-delay": `${Math.max(0, delay)}ms` } as CSSProperties}
    >
      {children}
    </div>
  );
}

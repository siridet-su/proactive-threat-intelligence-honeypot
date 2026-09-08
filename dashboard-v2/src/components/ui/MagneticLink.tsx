"use client";

import Link from "next/link";
import { useEffect, useRef, useState, type MouseEventHandler, type ReactNode } from "react";

interface MagneticLinkProps {
  href: string;
  className?: string;
  children: ReactNode;
  authenticatedHref?: string;
  loginHref?: string;
  onClick?: MouseEventHandler<HTMLAnchorElement>;
}

function navigate(destination: string) {
  window.location.assign(destination);
}

function loginDestination(destination: string) {
  return `/login?next=${encodeURIComponent(destination)}`;
}

export default function MagneticLink({ href, className, children, authenticatedHref, loginHref, onClick }: MagneticLinkProps) {
  const element = useRef<HTMLAnchorElement>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    const link = element.current;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
    if (!link || reducedMotion.matches || !finePointer.matches) return;

    let frame = 0;
    let nextX = 0;
    let nextY = 0;

    const applyOffset = () => {
      frame = 0;
      link.style.transform = `translate3d(${nextX.toFixed(2)}px, ${nextY.toFixed(2)}px, 0)`;
    };

    const queueOffset = () => {
      if (!frame) frame = window.requestAnimationFrame(applyOffset);
    };

    const handleMove = (event: PointerEvent) => {
      const bounds = link.getBoundingClientRect();
      const relativeX = (event.clientX - bounds.left) / bounds.width - 0.5;
      const relativeY = (event.clientY - bounds.top) / bounds.height - 0.5;
      nextX = relativeX * 5;
      nextY = relativeY * 4;
      queueOffset();
    };

    const handleLeave = () => {
      nextX = 0;
      nextY = 0;
      queueOffset();
    };

    link.addEventListener("pointermove", handleMove);
    link.addEventListener("pointerleave", handleLeave);

    return () => {
      if (frame) window.cancelAnimationFrame(frame);
      link.style.transform = "";
      link.removeEventListener("pointermove", handleMove);
      link.removeEventListener("pointerleave", handleLeave);
    };
  }, []);

  const handleClick: MouseEventHandler<HTMLAnchorElement> = async (event) => {
    onClick?.(event);
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      checking ||
      !authenticatedHref
    ) return;

    event.preventDefault();
    setChecking(true);
    try {
      const response = await fetch("/api/auth/session", { cache: "no-store", credentials: "same-origin" });
      navigate(response.ok ? authenticatedHref : (loginHref ?? loginDestination(authenticatedHref)));
    } catch {
      navigate(loginHref ?? loginDestination(authenticatedHref));
    }
  };

  return <Link ref={element} href={href} className={className} onClick={handleClick} aria-busy={checking || undefined}>{children}{checking && <span className="sr-only">Checking session…</span>}</Link>;
}

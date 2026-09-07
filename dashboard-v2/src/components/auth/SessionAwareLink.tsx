"use client";

import Link from "next/link";
import { useState, type ComponentProps, type MouseEventHandler } from "react";

type SessionAwareLinkProps = Omit<ComponentProps<typeof Link>, "href" | "onClick"> & {
  href: string;
  requiresSession?: boolean;
  authenticatedHref?: string;
  loginHref?: string;
  onClick?: MouseEventHandler<HTMLAnchorElement>;
};

function navigate(destination: string) {
  if (destination.startsWith("#")) {
    window.location.hash = destination.slice(1);
    return;
  }
  window.location.assign(destination);
}

function loginDestination(destination: string) {
  const next = destination.startsWith("#") ? `/${destination}` : destination;
  return `/login?next=${encodeURIComponent(next)}`;
}

export default function SessionAwareLink({
  href,
  requiresSession = true,
  authenticatedHref = href,
  loginHref,
  onClick,
  children,
  ...props
}: SessionAwareLinkProps) {
  const [checking, setChecking] = useState(false);

  const handleClick: MouseEventHandler<HTMLAnchorElement> = async (event) => {
    onClick?.(event);
    if (
      !requiresSession ||
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.altKey ||
      checking
    ) {
      return;
    }

    event.preventDefault();
    setChecking(true);

    try {
      const response = await fetch("/api/auth/session", {
        cache: "no-store",
        credentials: "same-origin",
      });
      navigate(response.ok ? authenticatedHref : (loginHref ?? loginDestination(authenticatedHref)));
    } catch {
      navigate(loginHref ?? loginDestination(authenticatedHref));
    }
  };

  return (
    <Link
      {...props}
      href={href}
      onClick={handleClick}
      aria-busy={checking || undefined}
      data-session-checking={checking ? "true" : undefined}
    >
      {children}
      {checking && <span className="sr-only">Checking session…</span>}
    </Link>
  );
}

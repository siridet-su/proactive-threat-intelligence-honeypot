"use client";

import Link from "next/link";
import { useEffect, useRef, type ReactNode } from "react";

interface MagneticLinkProps {
  href: string;
  className?: string;
  children: ReactNode;
}

export default function MagneticLink({ href, className, children }: MagneticLinkProps) {
  const element = useRef<HTMLAnchorElement>(null);

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

  return <Link ref={element} href={href} className={className}>{children}</Link>;
}

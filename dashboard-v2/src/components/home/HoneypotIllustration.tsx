"use client";

import { useEffect, useRef } from "react";

const VIEWBOX_WIDTH = 640;
const VIEWBOX_HEIGHT = 460;
const BEE_REPULSION_RADIUS = 118;
const NODE_REPULSION_RADIUS = 104;

const bees = [
  { x: 148, y: 144, driftX: 34, driftY: 18, speed: 0.54, phase: 0.3, scale: 0.8 },
  { x: 492, y: 124, driftX: 27, driftY: 25, speed: 0.47, phase: 2.1, scale: 0.68 },
  { x: 500, y: 298, driftX: 31, driftY: 17, speed: 0.38, phase: 4.5, scale: 0.6 },
  { x: 184, y: 330, driftX: 23, driftY: 21, speed: 0.43, phase: 5.7, scale: 0.56 },
] as const;

const networkNodes = [
  { x: 94, y: 182, radius: 5 },
  { x: 214, y: 94, radius: 4 },
  { x: 520, y: 202, radius: 5 },
  { x: 464, y: 366, radius: 4 },
  { x: 120, y: 360, radius: 3 },
] as const;

export default function HoneypotIllustration() {
  const illustration = useRef<SVGSVGElement>(null);
  const beeElements = useRef<Array<SVGGElement | null>>([]);
  const nodeElements = useRef<Array<SVGGElement | null>>([]);

  useEffect(() => {
    const svg = illustration.current;
    if (!svg) return;

    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
    if (reducedMotion.matches || !finePointer.matches) return;

    let frame = 0;
    let isInView = true;
    const pointer = { x: -1000, y: -1000 };

    const updateScene = (time: number) => {
      bees.forEach((bee, index) => {
        const phase = time * bee.speed + bee.phase;
        let x = bee.x + Math.sin(phase) * bee.driftX + Math.sin(phase * 0.47 + bee.phase) * 9;
        let y = bee.y + Math.cos(phase * 1.17) * bee.driftY + Math.sin(phase * 0.63) * 7;
        const distance = Math.hypot(x - pointer.x, y - pointer.y);

        if (distance > 0 && distance < BEE_REPULSION_RADIUS) {
          const force = Math.pow(1 - distance / BEE_REPULSION_RADIUS, 2) * 30;
          x += ((x - pointer.x) / distance) * force;
          y += ((y - pointer.y) / distance) * force;
        }

        const velocityX = Math.cos(phase) * bee.driftX * bee.speed;
        const velocityY = -Math.sin(phase * 1.17) * bee.driftY * bee.speed;
        const heading = Math.atan2(velocityY, velocityX) * (180 / Math.PI);
        beeElements.current[index]?.setAttribute("transform", `translate(${x.toFixed(2)} ${y.toFixed(2)}) rotate(${heading.toFixed(2)}) scale(${bee.scale})`);
      });

      networkNodes.forEach((node, index) => {
        const distance = Math.hypot(node.x - pointer.x, node.y - pointer.y);
        const force = distance > 0 && distance < NODE_REPULSION_RADIUS
          ? Math.pow(1 - distance / NODE_REPULSION_RADIUS, 2) * 7
          : 0;
        const x = force ? node.x + ((node.x - pointer.x) / distance) * force : node.x;
        const y = force ? node.y + ((node.y - pointer.y) / distance) * force : node.y;
        nodeElements.current[index]?.setAttribute("transform", `translate(${x.toFixed(2)} ${y.toFixed(2)})`);
      });
    };

    const tick = (timestamp: number) => {
      frame = 0;
      if (!isInView || document.hidden) return;
      updateScene(timestamp / 1000);
      frame = window.requestAnimationFrame(tick);
    };

    const start = () => {
      if (!frame && isInView && !document.hidden) frame = window.requestAnimationFrame(tick);
    };

    const stop = () => {
      if (frame) window.cancelAnimationFrame(frame);
      frame = 0;
    };

    const handlePointerMove = (event: PointerEvent) => {
      const bounds = svg.getBoundingClientRect();
      pointer.x = ((event.clientX - bounds.left) / bounds.width) * VIEWBOX_WIDTH;
      pointer.y = ((event.clientY - bounds.top) / bounds.height) * VIEWBOX_HEIGHT;
    };

    const handlePointerLeave = () => {
      pointer.x = -1000;
      pointer.y = -1000;
    };

    const handleVisibility = () => {
      if (document.hidden) stop();
      else start();
    };

    const observer = new IntersectionObserver(([entry]) => {
      isInView = Boolean(entry?.isIntersecting);
      if (isInView) start();
      else stop();
    }, { threshold: 0.12 });

    svg.addEventListener("pointermove", handlePointerMove);
    svg.addEventListener("pointerleave", handlePointerLeave);
    document.addEventListener("visibilitychange", handleVisibility);
    observer.observe(svg);
    start();

    return () => {
      stop();
      observer.disconnect();
      svg.removeEventListener("pointermove", handlePointerMove);
      svg.removeEventListener("pointerleave", handlePointerLeave);
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, []);

  return (
    <div className="pti-honeypot-scene relative mx-auto w-full max-w-xl">
      <div className="ui-panel overflow-hidden p-3 sm:p-4">
        <div className="flex items-center justify-between gap-3 border-b border-border pb-3 text-xs">
          <span className="flex items-center gap-2 font-semibold text-text"><span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />Operator workspace</span>
          <span className="ui-badge border-primary-border bg-primary-subtle text-primary">Read-only</span>
        </div>
        <div className="mt-3 overflow-hidden rounded-lg border border-border bg-surface-subtle p-2 sm:p-3">
          <svg ref={illustration} viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`} className="pti-hero-visual h-auto w-full" role="img" aria-label="A monitored network directing suspicious activity toward a honeypot and operator workspace">
            <g aria-hidden="true" className="pti-honeycomb-field" fill="none" stroke="var(--primary-border)" strokeWidth="1.25">
              <path d="M70 68 91 56 112 68 112 92 91 104 70 92Z M113 68 134 56 155 68 155 92 134 104 113 92Z M91 105 112 93 133 105 133 129 112 141 91 129Z" />
              <path d="M487 323 508 311 529 323 529 347 508 359 487 347Z M530 323 551 311 572 323 572 347 551 359 530 347Z M508 360 529 348 550 360 550 384 529 396 508 384Z" />
            </g>

            <g aria-hidden="true">
              <circle cx="320" cy="228" r="174" fill="var(--primary-subtle)" />
              <circle cx="320" cy="228" r="133" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2" />
              <circle cx="320" cy="228" r="102" fill="none" stroke="var(--border)" strokeWidth="1.5" strokeDasharray="5 12" />
              <path className="pti-telemetry-path pti-telemetry-path-one" d="M92 182 C166 126 204 172 268 202" fill="none" stroke="var(--info)" strokeWidth="2" strokeLinecap="round" />
              <path className="pti-telemetry-path pti-telemetry-path-two" d="M523 201 C468 178 448 228 379 242" fill="none" stroke="var(--primary)" strokeWidth="2" strokeLinecap="round" />
              <path className="pti-telemetry-path pti-telemetry-path-three" d="M461 365 C424 318 395 310 362 288" fill="none" stroke="var(--info)" strokeWidth="2" strokeLinecap="round" />
              <path d="M118 360 C186 328 221 314 266 290" fill="none" stroke="var(--border-strong)" strokeWidth="1.5" strokeDasharray="3 10" />
            </g>

            <g aria-hidden="true">
              {networkNodes.map((node, index) => (
                <g key={`${node.x}-${node.y}`} ref={(element) => { nodeElements.current[index] = element; }} className="pti-hero-network-node" transform={`translate(${node.x} ${node.y})`}>
                  <circle r={node.radius + 4} fill="var(--primary-subtle)" />
                  <circle r={node.radius} fill="var(--primary)" />
                </g>
              ))}
            </g>

            <g aria-hidden="true">
              <ellipse cx="320" cy="335" rx="126" ry="19" fill="var(--illustration-honey-deep)" opacity="0.82" />
              <path d="M205 278 C205 355 244 392 320 392 C396 392 435 355 435 278Z" fill="var(--surface-raised)" stroke="var(--border-strong)" strokeWidth="3" />
              <path d="M218 279 C236 259 281 250 320 250 C359 250 404 259 422 279 C403 299 358 307 320 307 C282 307 237 299 218 279Z" fill="var(--illustration-honey)" stroke="var(--illustration-honey-deep)" strokeWidth="3" />
              <path d="M251 277 C266 266 291 262 320 262 C349 262 374 266 389 277 C373 289 348 293 320 293 C292 293 267 289 251 277Z" fill="var(--illustration-honey-light)" />
              <path d="M262 329 H378 M278 353 H362" stroke="var(--illustration-honey)" strokeWidth="8" strokeLinecap="round" />
              <path d="M320 219 V247" stroke="var(--primary)" strokeWidth="2" strokeDasharray="4 7" />
              <circle cx="320" cy="217" r="7" fill="var(--primary-subtle)" stroke="var(--primary)" strokeWidth="2" />
            </g>

            <g aria-hidden="true">
              {bees.map((bee, index) => (
                <g key={`${bee.x}-${bee.y}`} ref={(element) => { beeElements.current[index] = element; }} className="pti-hero-bee" transform={`translate(${bee.x} ${bee.y}) scale(${bee.scale})`}>
                  <path d="M-8 -17 C-28 -33 -43 -13 -23 -1 C-40 9 -23 28 -5 12" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2.5" strokeLinejoin="round" />
                  <path d="M3 -16 C25 -34 39 -11 21 1 C39 12 21 29 3 12" fill="var(--surface)" stroke="var(--primary-border)" strokeWidth="2.5" strokeLinejoin="round" />
                  <path d="M-19 -9 H12 C25 -9 31 0 31 9 C31 18 24 25 11 25 H-18 C-31 25 -37 16 -37 8 C-37 0 -31 -9 -19 -9Z" fill="var(--illustration-honey)" stroke="var(--illustration-honey-deep)" strokeWidth="3" />
                  <path d="M-16 -8 V24 M-2 -8 V24 M12 -7 V24" stroke="var(--text)" strokeWidth="4" />
                  <path d="M31 2 C43 3 47 11 42 17 C38 21 32 20 28 16" fill="var(--text)" />
                </g>
              ))}
            </g>
          </svg>
        </div>
        <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
          {[
            ["01", "Session evidence"],
            ["02", "Origin context"],
            ["03", "Review queue"],
          ].map(([index, label]) => (
            <div key={label} className="rounded-lg border border-border bg-surface p-3 transition-colors duration-150 hover:border-border-strong hover:bg-surface-hover">
              <span className="block font-mono text-text-subtle">{index}</span>
              <span className="mt-1 block font-medium text-text">{label}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-3 flex items-center justify-between gap-3 px-1 text-sm text-text-muted">
        <span>A convincing decoy, built to be investigated.</span>
        <span className="font-mono text-xs text-text-subtle">PTI / OPS</span>
      </div>
    </div>
  );
}

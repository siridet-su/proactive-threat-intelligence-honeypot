"use client";

import Image from "next/image";
import { motion, useReducedMotion } from "framer-motion";

const flightPatterns = [
  {
    asset: "/images/landing/cyber-bee-flight-one.webp",
    className: "pti-honeypot-bee pti-honeypot-bee-one",
    duration: 6.4,
    delay: -1.3,
    movement: { x: [0, 18, -8, 0], y: [0, -12, 8, 0], rotate: [-8, 4, -3, -8] },
  },
  {
    asset: "/images/landing/cyber-bee-flight-two.webp",
    className: "pti-honeypot-bee pti-honeypot-bee-two",
    duration: 7.2,
    delay: -3.8,
    movement: { x: [0, -14, 10, 0], y: [0, 12, -8, 0], rotate: [8, -4, 5, 8] },
  },
  {
    asset: "/images/landing/cyber-bee-flight-three.webp",
    className: "pti-honeypot-bee pti-honeypot-bee-three",
    duration: 5.8,
    delay: -2.1,
    movement: { x: [0, 12, -6, 0], y: [0, -14, 5, 0], rotate: [-4, 5, 1, -4] },
  },
];

export default function HoneypotIllustration() {
  const reduceMotion = useReducedMotion();

  return (
    <div className="pti-honeypot-scene relative mx-auto w-full max-w-xl">
      <div className="pti-honeypot-workspace-row flex items-center justify-between gap-3 px-1 pb-3 text-xs sm:px-2">
        <span className="flex items-center gap-2 font-semibold text-text"><span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />Operator workspace</span>
        <span className="ui-badge border-primary-border bg-primary-subtle text-primary">Read-only</span>
      </div>

      <div
        className="pti-honeypot-asset-stage mt-3"
        role="img"
        aria-label="A protected glass honey vessel monitored by three honey bees"
      >
        <span className="pti-honeypot-orbit pti-honeypot-orbit-one" aria-hidden="true" />
        <span className="pti-honeypot-orbit pti-honeypot-orbit-two" aria-hidden="true" />
        <span className="pti-honeypot-signal pti-honeypot-signal-one" aria-hidden="true" />
        <span className="pti-honeypot-signal pti-honeypot-signal-two" aria-hidden="true" />
        <span className="pti-honeypot-node pti-honeypot-node-one" aria-hidden="true" />
        <span className="pti-honeypot-node pti-honeypot-node-two" aria-hidden="true" />

        <div className="pti-honeypot-device-frame">
          <motion.div
            className="pti-honeypot-device"
            animate={reduceMotion ? undefined : { y: [0, -5, 0], rotate: [0, 0.45, 0] }}
            transition={{ duration: 6.8, ease: "easeInOut", repeat: Infinity }}
          >
            <Image
              src="/images/landing/cyber-honeypot-device.webp"
              alt=""
              width={960}
              height={640}
              priority
              sizes="(max-width: 640px) 94vw, 32rem"
            />
          </motion.div>
        </div>

        {flightPatterns.map(({ asset, className, duration, delay, movement }) => (
          <motion.div
            key={asset}
            className={className}
            animate={reduceMotion ? undefined : movement}
            transition={{ duration, delay, ease: "easeInOut", repeat: Infinity }}
          >
            <Image src={asset} alt="" width={640} height={427} sizes="(max-width: 640px) 11rem, 14rem" />
          </motion.div>
        ))}

        <span className="pti-honeypot-stage-label pti-honeypot-stage-label-top" aria-hidden="true">DECOY NODE</span>
        <span className="pti-honeypot-stage-label pti-honeypot-stage-label-bottom" aria-hidden="true">INSPECTED / SAFE</span>
      </div>

      <div className="mt-3 grid grid-cols-3 gap-2 text-xs sm:px-2">
        {[
          ["01", "Session evidence"],
          ["02", "Origin context"],
          ["03", "Review queue"],
        ].map(([index, label]) => (
          <div key={label} className="pti-honeypot-evidence-card rounded-lg border border-border p-3 transition-colors duration-150 hover:border-border-strong hover:bg-surface-hover">
            <span className="block font-mono text-text-subtle">{index}</span>
            <span className="mt-1 block font-medium text-text">{label}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 flex items-center justify-between gap-3 px-1 text-sm text-text-muted">
        <span>A convincing decoy, built to be investigated.</span>
        <span className="font-mono text-xs text-text-subtle">PTI / OPS</span>
      </div>
    </div>
  );
}

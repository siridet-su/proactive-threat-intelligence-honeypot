import HoneypotIllustration from "./HoneypotIllustration";
import SessionAwareLink from "@/components/auth/SessionAwareLink";
import MagneticLink from "@/components/ui/MagneticLink";

export default function HeroSection() {
  return (
    <section id="overview" className="pti-hive-hero relative isolate overflow-hidden scroll-mt-24">
      <div className="pti-hive-hero-grid pointer-events-none absolute inset-0" aria-hidden="true">
        <svg viewBox="0 0 1440 820" preserveAspectRatio="xMidYMid slice" className="h-full w-full text-primary">
          <defs>
            <pattern id="hero-honeycomb-grid" width="96" height="84" patternUnits="userSpaceOnUse">
              <path d="M24 2H72L95 42 72 82H24L1 42Z" fill="none" stroke="currentColor" strokeWidth="1" />
            </pattern>
            <pattern id="hero-honeycomb-spark-a" width="96" height="84" patternUnits="userSpaceOnUse" patternTransform="rotate(0)">
              <path className="pti-hive-grid-spark pti-hive-grid-spark-a" d="M24 2H72L95 42 72 82H24L1 42Z" fill="none" stroke="currentColor" strokeWidth="1.7" pathLength="100" />
            </pattern>
            <pattern id="hero-honeycomb-spark-b" width="96" height="84" patternUnits="userSpaceOnUse" patternTransform="translate(48 42)">
              <path className="pti-hive-grid-spark pti-hive-grid-spark-b" d="M24 2H72L95 42 72 82H24L1 42Z" fill="none" stroke="currentColor" strokeWidth="1.4" pathLength="100" />
            </pattern>
            <pattern id="hero-honeycomb-spark-c" width="96" height="84" patternUnits="userSpaceOnUse" patternTransform="translate(24 0)">
              <path className="pti-hive-grid-spark pti-hive-grid-spark-c" d="M24 2H72L95 42 72 82H24L1 42Z" fill="none" stroke="currentColor" strokeWidth="1.2" pathLength="100" />
            </pattern>
          </defs>
          <rect width="1440" height="820" fill="url(#hero-honeycomb-grid)" opacity="0.17" />
          <rect className="pti-hive-grid-spark-layer" width="1440" height="820" fill="url(#hero-honeycomb-spark-a)" opacity="0.58" />
          <rect className="pti-hive-grid-spark-layer" width="1440" height="820" fill="url(#hero-honeycomb-spark-b)" opacity="0.42" />
          <rect className="pti-hive-grid-spark-layer" width="1440" height="820" fill="url(#hero-honeycomb-spark-c)" opacity="0.3" />
          <path d="M0 636 C258 508 328 688 556 520 S924 537 1136 375 S1280 400 1440 272" fill="none" stroke="currentColor" strokeWidth="1.4" strokeDasharray="5 16" opacity="0.34" />
          <path d="M-20 204 C176 98 301 253 462 168 S822 284 1016 154 S1270 176 1480 58" fill="none" stroke="currentColor" strokeWidth="1" strokeDasharray="3 13" opacity="0.25" />
        </svg>
      </div>
      <div className="pti-hive-hero-orb pti-hive-hero-orb-one pointer-events-none absolute" aria-hidden="true" />
      <div className="pti-hive-hero-orb pti-hive-hero-orb-two pointer-events-none absolute" aria-hidden="true" />
      <div className="relative mx-auto grid w-full max-w-7xl items-center gap-12 px-6 py-16 sm:px-10 sm:py-24 lg:grid-cols-[0.84fr_1.16fr] lg:gap-14 lg:py-28">
        <div className="max-w-2xl">
          <div className="pti-hero-reveal inline-flex items-center gap-3 rounded-full border border-primary-border bg-primary-subtle/90 px-3 py-2 text-xs font-semibold text-primary">
            <span className="h-2 w-2 rounded-full bg-primary shadow-[0_0_10px_var(--primary)]" aria-hidden="true" />
            Proactive threat intelligence
          </div>
          <h1 className="pti-hero-reveal pti-hero-reveal-delay-1 mt-6 max-w-xl text-5xl font-semibold leading-[0.98] tracking-[-0.045em] text-text sm:text-6xl lg:text-7xl">Deceive.<br /><span className="text-primary">Detect.</span> Defend.</h1>
          <p className="pti-hero-reveal pti-hero-reveal-delay-2 mt-7 max-w-xl text-base leading-7 text-text-muted sm:text-lg sm:leading-8">
            Proactive threat intelligence powered by next-generation honeypots. Observe attacker behavior before it reaches production.
          </p>
          <div className="pti-hero-reveal pti-hero-reveal-delay-3 mt-9 flex flex-wrap gap-3">
            <MagneticLink href="/login" className="ui-button ui-button-primary pti-magnetic-link pti-hive-primary-cta group px-6">
              View live dashboard
              <svg className="pti-button-arrow h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M4 12h15" /></svg>
            </MagneticLink>
            <SessionAwareLink href="#documentation" className="ui-button pti-hive-secondary-cta group px-6">Documentation <span className="pti-button-arrow" aria-hidden="true">↓</span></SessionAwareLink>
          </div>
          <div className="pti-hero-reveal pti-hero-reveal-delay-4 mt-9 flex flex-wrap gap-x-5 gap-y-2 text-sm text-text-muted">
            <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />Read-only by design</span>
            <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-info" aria-hidden="true" />Operator-focused workflow</span>
          </div>
        </div>
        <div className="pti-hero-reveal pti-hero-reveal-delay-3 w-full"><HoneypotIllustration /></div>
      </div>
    </section>
  );
}

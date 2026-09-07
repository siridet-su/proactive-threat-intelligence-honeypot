import Link from "next/link";
import HoneypotIllustration from "./HoneypotIllustration";
import MagneticLink from "@/components/ui/MagneticLink";

export default function HeroSection() {
  return (
    <section id="overview" className="mx-auto grid w-full max-w-7xl scroll-mt-24 items-center gap-12 px-6 py-14 sm:px-10 sm:py-20 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16 lg:py-24">
      <div className="max-w-2xl">
        <div className="pti-hero-reveal inline-flex items-center gap-3 rounded-full border border-primary-border bg-primary-subtle px-3 py-2 text-xs font-semibold text-primary">
          <span className="h-2 w-2 rounded-full bg-primary" aria-hidden="true" />
          Proactive threat intelligence
        </div>
        <h1 className="pti-hero-reveal pti-hero-reveal-delay-1 mt-6 max-w-xl text-4xl font-semibold leading-tight tracking-tight text-text sm:text-5xl sm:leading-[1.08]">Observe attacker behavior before it reaches production.</h1>
        <p className="pti-hero-reveal pti-hero-reveal-delay-2 mt-6 max-w-xl text-base leading-7 text-text-muted sm:text-lg sm:leading-8">
          PTI-Honeypot gives security operators a focused, read-only workspace for decoy sessions, origin context, captured evidence, and sensor health.
        </p>
        <div className="pti-hero-reveal pti-hero-reveal-delay-3 mt-8 flex flex-wrap gap-3">
          <MagneticLink href="/login" className="ui-button ui-button-primary pti-magnetic-link group px-6">
            Open operator console
            <svg className="pti-button-arrow h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M4 12h15" /></svg>
          </MagneticLink>
          <Link href="#how-it-works" className="ui-button group px-6">See how it works <span className="pti-button-arrow" aria-hidden="true">↓</span></Link>
        </div>
        <div className="pti-hero-reveal pti-hero-reveal-delay-4 mt-8 flex flex-wrap gap-x-5 gap-y-2 text-sm text-text-muted">
          <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />Read-only by design</span>
          <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-info" aria-hidden="true" />Operator-focused workflow</span>
        </div>
      </div>
      <div className="pti-hero-reveal pti-hero-reveal-delay-3 w-full"><HoneypotIllustration /></div>
    </section>
  );
}

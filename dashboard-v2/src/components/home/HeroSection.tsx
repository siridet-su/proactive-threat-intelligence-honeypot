import Link from "next/link";
import HoneypotIllustration from "./HoneypotIllustration";

export default function HeroSection() {
  return (
    <section id="overview" className="mx-auto grid w-full max-w-7xl scroll-mt-24 items-center gap-10 px-6 py-14 sm:px-10 sm:py-20 lg:grid-cols-[1.02fr_0.98fr] lg:gap-16 lg:py-24">
      <div className="max-w-2xl">
        <div className="mb-6 inline-flex items-center gap-3 rounded-full border border-primary-border bg-primary-subtle px-4 py-2 text-sm font-semibold text-primary">
          <span className="h-2 w-2 rounded-full bg-primary" />
          Vigilance Through Deception
        </div>
        <h1 className="text-4xl font-semibold leading-tight tracking-tight text-text sm:text-5xl lg:text-[56px] lg:leading-[1.06]">PTI-HONEYPOT</h1>
        <p className="mt-6 max-w-xl text-lg leading-8 text-text-muted">
          Advanced Cyber Intelligence &amp; Decoy Operations. Neutralize threats by becoming the target they can&apos;t resist. High-fidelity honeypot systems for the modern enterprise.
        </p>
        <div className="mt-9 flex flex-wrap gap-3">
          <Link href="/login" className="ui-button ui-button-primary px-6">
            Get started
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 5l7 7-7 7M4 12h15" /></svg>
          </Link>
          <Link href="/login" className="ui-button px-6">Access terminal</Link>
        </div>
      </div>
      <HoneypotIllustration />
    </section>
  );
}

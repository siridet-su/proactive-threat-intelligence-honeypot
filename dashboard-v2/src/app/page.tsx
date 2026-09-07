import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import HeroSection from "@/components/home/HeroSection";
import HoneycombFeatureGrid from "@/components/home/HoneycombFeatureGrid";
import ThreatPreview from "@/components/home/ThreatPreview";
import SessionAwareLink from "@/components/auth/SessionAwareLink";
import ScrollReveal from "@/components/ui/ScrollReveal";

export default function Home() {
  return (
    <main className="pti-cyber-landing min-h-dvh bg-canvas text-text">
      <Navbar />

      <div className="flex flex-col">
        <HeroSection />

        <section id="capabilities" aria-labelledby="capabilities-title" className="pti-hive-section relative overflow-hidden scroll-mt-24 border-y border-border px-6 py-20 sm:px-10 lg:py-28">
          <div className="pti-hive-section-mark pti-hive-section-mark-left" aria-hidden="true" />
          <div className="relative mx-auto w-full max-w-7xl">
            <ScrollReveal className="mx-auto max-w-2xl text-center">
              <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">The hive mind</p>
              <h2 id="capabilities-title" className="mt-4 text-3xl font-semibold tracking-tight sm:text-4xl">Investigation surfaces, built as one system.</h2>
              <p className="mt-4 text-base leading-7 text-text-muted">Keep the signal readable from first observation through evidence review, without turning the console into a wall of noise.</p>
            </ScrollReveal>
            <HoneycombFeatureGrid />
          </div>
        </section>

        <section id="how-it-works" aria-labelledby="how-it-works-title" className="scroll-mt-24 bg-surface-subtle">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-6 py-16 sm:px-10 lg:grid-cols-[0.75fr_1.25fr] lg:items-start lg:py-20">
            <ScrollReveal>
              <div>
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Signal path</p>
                <h2 id="how-it-works-title" className="mt-3 text-3xl font-semibold tracking-tight sm:text-[32px]">From decoy to defensible context.</h2>
                <p className="mt-3 text-sm leading-6 text-text-muted sm:text-base">The operator experience is organized around the decisions that matter: what happened, where it came from, and what evidence is available.</p>
              </div>
            </ScrollReveal>
            <ScrollReveal delay={80}>
              <ol className="grid gap-3">
                {[
                  ["Deploy", "Place a convincing decoy at the edge of your monitored environment."],
                  ["Observe", "Capture sessions and keep the live feed understandable as activity changes."],
                  ["Investigate", "Open the session detail view when a record needs deeper review."],
                ].map(([title, description], index) => (
                <li key={title} className="relative flex gap-4 rounded-xl border border-border bg-surface p-5 shadow-[var(--shadow-card)] sm:p-6">
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-subtle font-mono text-sm font-semibold text-primary">{String(index + 1).padStart(2, "0")}</span>
                  <div>
                    <h3 className="text-base font-semibold">{title}</h3>
                    <p className="mt-1 text-sm leading-6 text-text-muted">{description}</p>
                  </div>
                  {index < 2 && <span className="pti-flow-connector pointer-events-none absolute left-9 top-full z-10 h-3 w-px bg-border" aria-hidden="true"><span className="pti-flow-pulse absolute left-1/2 top-0 h-2 w-2 -translate-x-1/2 rounded-full bg-primary" /></span>}
                </li>
                ))}
              </ol>
            </ScrollReveal>
          </div>
        </section>

        <ThreatPreview />

        <section id="documentation" aria-labelledby="documentation-title" className="mx-auto w-full max-w-7xl scroll-mt-24 px-6 py-16 sm:px-10 lg:py-20">
          <ScrollReveal>
            <div className="pti-hive-callout ui-panel flex flex-col justify-between gap-8 overflow-hidden p-6 sm:p-8 lg:flex-row lg:items-center">
              <div className="max-w-2xl">
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Documentation &amp; access</p>
                <h2 id="documentation-title" className="mt-3 text-3xl font-semibold tracking-tight">Start with a controlled deployment.</h2>
                <p className="mt-3 text-sm leading-6 text-text-muted sm:text-base">Authorized operators can sign in to access the read-only intelligence workspace and its deployment workflow.</p>
                <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-sm text-text-muted">
                  <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />Read-only evidence</span>
                  <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-info" aria-hidden="true" />Same-origin console</span>
                </div>
              </div>
              <SessionAwareLink href="/login" authenticatedHref="/dashboard" className="ui-button ui-button-primary shrink-0 px-6">Open operator console</SessionAwareLink>
            </div>
          </ScrollReveal>
        </section>
      </div>

      <Footer />
    </main>
  );
}

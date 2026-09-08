import Link from "next/link";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import HeroSection from "@/components/home/HeroSection";

export default function Home() {
  return (
    <main className="min-h-dvh bg-canvas text-text">
      <Navbar />

      <div className="flex flex-col">
        <HeroSection />

        <section id="capabilities" aria-labelledby="capabilities-title" className="mx-auto w-full max-w-7xl scroll-mt-24 px-6 py-16 sm:px-10 lg:py-20">
          <div className="max-w-2xl">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Operator workspace</p>
            <h2 id="capabilities-title" className="mt-3 text-2xl font-semibold tracking-tight sm:text-[28px]">Everything needed to investigate a session.</h2>
            <p className="mt-3 text-sm leading-6 text-text-muted sm:text-base">Keep the signal readable from first observation through evidence review, without turning the console into a wall of noise.</p>
          </div>

          <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {[
              { eyebrow: "01", title: "Session intelligence", description: "Review observed sessions, origin details, classifications, and duration from one queue.", href: "/login", action: "Open console" },
              { eyebrow: "02", title: "Origin mapping", description: "Use geographic context to move from a broad attack surface to a specific session.", href: "/login", action: "View workspace" },
              { eyebrow: "03", title: "Evidence review", description: "Keep captured artifacts and session detail close to the investigation workflow.", href: "/login", action: "Review evidence" },
              { eyebrow: "04", title: "Sensor health", description: "Monitor the telemetry surface that supports the operator view and its refresh state.", href: "/login", action: "Check health" },
            ].map((item) => (
              <Link key={item.title} href={item.href} className="ui-panel ui-panel-interactive group flex min-h-52 flex-col p-5 focus-visible:border-primary sm:p-6">
                <span className="font-mono text-xs font-semibold text-primary">{item.eyebrow}</span>
                <h3 className="mt-5 text-base font-semibold">{item.title}</h3>
                <p className="mt-2 flex-1 text-sm leading-6 text-text-muted">{item.description}</p>
                <span className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-primary">
                  {item.action}
                  <span aria-hidden="true" className="transition-transform duration-150 group-hover:translate-x-1">→</span>
                </span>
              </Link>
            ))}
          </div>
        </section>

        <section id="how-it-works" aria-labelledby="how-it-works-title" className="border-y border-border bg-surface-subtle scroll-mt-24">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-6 py-16 sm:px-10 lg:grid-cols-[0.75fr_1.25fr] lg:items-start lg:py-20">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">How it works</p>
              <h2 id="how-it-works-title" className="mt-3 text-2xl font-semibold tracking-tight sm:text-[28px]">A calm path from signal to context.</h2>
              <p className="mt-3 text-sm leading-6 text-text-muted sm:text-base">The operator experience is organized around the decisions that matter: what happened, where it came from, and what evidence is available.</p>
            </div>
            <ol className="grid gap-3">
              {[
                ["Deploy", "Place a convincing decoy at the edge of your monitored environment."],
                ["Observe", "Capture sessions and keep the live feed understandable as activity changes."],
                ["Investigate", "Open the session detail view when a record needs deeper review."],
              ].map(([title, description], index) => (
                <li key={title} className="flex gap-4 rounded-xl border border-border bg-surface p-5 shadow-[var(--shadow-card)] sm:p-6">
                  <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-primary-border bg-primary-subtle font-mono text-sm font-semibold text-primary">{String(index + 1).padStart(2, "0")}</span>
                  <div>
                    <h3 className="text-base font-semibold">{title}</h3>
                    <p className="mt-1 text-sm leading-6 text-text-muted">{description}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section id="documentation" aria-labelledby="documentation-title" className="mx-auto w-full max-w-7xl scroll-mt-24 px-6 py-16 sm:px-10 lg:py-20">
          <div className="ui-panel flex flex-col justify-between gap-8 p-6 sm:p-8 lg:flex-row lg:items-center">
            <div className="max-w-2xl">
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Documentation &amp; access</p>
              <h2 id="documentation-title" className="mt-3 text-2xl font-semibold tracking-tight">Start with a controlled deployment.</h2>
              <p className="mt-3 text-sm leading-6 text-text-muted sm:text-base">Authorized operators can sign in to access the read-only intelligence workspace and its deployment workflow.</p>
              <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-sm text-text-muted">
                <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-success" aria-hidden="true" />Read-only evidence</span>
                <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-info" aria-hidden="true" />Same-origin console</span>
              </div>
            </div>
            <Link href="/login" className="ui-button ui-button-primary shrink-0 px-6">Open operator console</Link>
          </div>
        </section>
      </div>

      <Footer />
    </main>
  );
}

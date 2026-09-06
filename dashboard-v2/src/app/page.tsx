import Link from "next/link";
import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import HeroSection from "@/components/home/HeroSection";

export default function Home() {
  return (
    <main className="min-h-dvh bg-canvas flex flex-col">
      <Navbar />
      
      <div className="flex flex-1 flex-col justify-center">
        <HeroSection />
        <section id="documentation" aria-labelledby="documentation-title" className="mx-auto mb-14 w-[calc(100%-3rem)] max-w-7xl scroll-mt-24 rounded-2xl border border-border bg-surface p-6 shadow-[var(--shadow-card)] sm:p-8">
          <div className="flex flex-col justify-between gap-6 md:flex-row md:items-center">
            <div className="max-w-2xl">
              <p className="text-sm font-semibold text-primary">DOCUMENTATION</p>
              <h2 id="documentation-title" className="mt-2 text-2xl font-semibold tracking-tight text-text">Start with a controlled deployment.</h2>
              <p className="mt-3 text-base text-text-muted">Sign in to access the operator workspace and its deployment documentation.</p>
            </div>
            <Link href="/login" className="ui-button ui-button-primary shrink-0 px-6">Get started</Link>
          </div>
        </section>
      </div>

      <Footer />
    </main>
  );
}

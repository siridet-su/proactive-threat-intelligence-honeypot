import LoginForm from "@/components/auth/LoginForm";
import ThemeToggle from "@/components/theme/ThemeToggle";
import Link from "next/link";

export default function LoginPage() {
  return (
    <main className="pti-auth-entry min-h-dvh bg-canvas text-text">
      <header className="flex min-h-16 items-center justify-between gap-4 border-b border-border bg-surface/90 px-4 py-3 sm:px-8">
        <Link href="/" className="flex items-center gap-3 text-base font-semibold">
          <span className="grid h-8 w-8 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary" aria-hidden="true">P</span>
          PTI-Honeypot
        </Link>
        <div className="flex items-center gap-2 sm:gap-3">
          <Link href="/" className="hidden text-sm font-medium text-text-muted transition-colors duration-150 hover:text-text focus-visible:outline-none sm:inline-flex">Back to landing</Link>
          <ThemeToggle />
        </div>
      </header>
      <section className="pti-auth-stage flex min-h-[calc(100dvh-4rem)] items-center px-4 py-10 sm:px-8 sm:py-14">
        <div className="mx-auto grid w-full max-w-6xl items-center gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:gap-16">
          <aside className="hidden max-w-lg lg:block" aria-label="Operator access information">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-primary">Controlled access</p>
            <h2 className="mt-4 text-4xl font-semibold leading-tight tracking-tight text-text">Enter the operator workspace.</h2>
            <p className="mt-5 max-w-md text-base leading-7 text-text-muted">Use your authorized operator credentials to access the read-only workspace.</p>
            <div className="pti-auth-trust-grid mt-9 grid grid-cols-3 gap-3 text-sm">
              <div><span className="text-primary">01</span><p>Authorized credentials</p></div>
              <div><span className="text-primary">02</span><p>Read-only workspace</p></div>
              <div><span className="text-primary">03</span><p>Monitored access</p></div>
            </div>
            <div className="pti-auth-hive-mark" aria-hidden="true"><span /><span /><span /></div>
          </aside>
          <div className="flex justify-center lg:justify-end"><LoginForm /></div>
        </div>
      </section>
    </main>
  );
}

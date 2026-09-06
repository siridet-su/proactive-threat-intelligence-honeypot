import Link from "next/link";
import ThemeToggle from "@/components/theme/ThemeToggle";

export default function Navbar() {
  return (
    <nav className="sticky top-0 z-40 flex w-full flex-wrap items-center justify-between gap-4 border-b border-border bg-surface px-5 py-4 shadow-[var(--shadow-card)] sm:px-8">
      <Link href="/" className="text-lg font-semibold tracking-tight text-text">PTI-Honeypot</Link>

      <div className="order-3 flex w-full items-center gap-1 overflow-x-auto text-sm font-medium text-text-muted sm:order-none sm:w-auto">
        <Link href="#overview" className="rounded-lg px-3 py-2 hover:bg-surface-hover hover:text-text">Overview</Link>
        <Link href="#documentation" className="rounded-lg px-3 py-2 hover:bg-surface-hover hover:text-text">Documentation</Link>
        <Link href="/login" className="rounded-lg px-3 py-2 hover:bg-surface-hover hover:text-text">Get started</Link>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <ThemeToggle />
        <Link href="/login" className="ui-button ui-button-primary px-5">Sign in</Link>
      </div>
    </nav>
  );
}

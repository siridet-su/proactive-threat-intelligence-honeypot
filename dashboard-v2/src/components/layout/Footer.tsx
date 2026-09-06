import Link from "next/link";

export default function Footer() {
  return (
    <footer className="w-full border-t border-border bg-surface px-5 py-8 text-sm leading-6 text-text-muted sm:px-8">
      <div>
        <p className="font-semibold text-text">PTI-Honeypot</p>
        <p className="mt-1">Read-only threat intelligence for authorized operators.</p>
      </div>
      <nav aria-label="Footer navigation" className="mt-6 flex flex-wrap gap-x-6 gap-y-2">
        <Link href="#overview" className="hover:text-primary">Overview</Link>
        <Link href="#documentation" className="hover:text-primary">Documentation</Link>
        <Link href="/login" className="hover:text-primary">Operator sign in</Link>
      </nav>
    </footer>
  );
}

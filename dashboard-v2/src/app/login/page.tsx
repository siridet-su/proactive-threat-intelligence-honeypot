import LoginForm from "@/components/auth/LoginForm";
import ThemeToggle from "@/components/theme/ThemeToggle";
import Link from "next/link";

export default function LoginPage() {
  return (
    <main className="min-h-dvh bg-canvas text-text">
      <header className="flex min-h-16 items-center justify-between gap-4 border-b border-border bg-surface px-4 py-3 sm:px-8">
        <Link href="/" className="flex items-center gap-3 text-base font-semibold">
          <span className="grid h-8 w-8 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary" aria-hidden="true">P</span>
          PTI-Honeypot
        </Link>
        <ThemeToggle />
      </header>
      <div className="flex flex-1 items-center justify-center px-4 py-12 sm:py-16"><LoginForm /></div>
    </main>
  );
}

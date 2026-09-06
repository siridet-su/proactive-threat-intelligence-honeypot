import LoginForm from "@/components/auth/LoginForm";
import ThemeToggle from "@/components/theme/ThemeToggle";

export default function LoginPage() {
  return (
    <main className="min-h-dvh bg-canvas flex flex-col">
      <header className="flex min-h-16 flex-wrap items-center justify-between gap-4 border-b border-border bg-surface px-4 py-3 sm:px-8">
        <div className="text-base font-semibold">PTI-Honeypot</div>
        <ThemeToggle />
      </header>
      <div className="flex flex-1 items-center justify-center px-4 py-10"><LoginForm /></div>
    </main>
  );
}

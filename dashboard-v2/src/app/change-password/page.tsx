"use client";

import { useState } from "react";
import Link from "next/link";
import { ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";

import ThemeToggle from "@/components/theme/ThemeToggle";

export default function ChangePasswordPage() {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    try {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ newPassword }),
      });

      if (res.ok) {
        router.push("/dashboard");
      } else {
        setError("Failed to update password. Please try again.");
      }
    } catch {
      setError("The password service is unavailable. Please try again.");
    }
  };

  return (
    <main className="min-h-dvh bg-canvas text-text">
      <header className="flex min-h-16 items-center justify-between gap-4 border-b border-border bg-surface px-4 py-3 sm:px-8">
        <Link href="/" className="flex items-center gap-3 text-base font-semibold">
          <span className="grid h-8 w-8 place-items-center rounded-lg border border-primary-border bg-primary-subtle text-primary" aria-hidden="true">P</span>
          PTI-Honeypot
        </Link>
        <ThemeToggle />
      </header>

      <div className="flex min-h-[calc(100dvh-4rem)] items-center justify-center px-4 py-12 sm:py-16">
        <section aria-labelledby="change-password-title" className="ui-panel w-full max-w-md">
          <div className="p-6 sm:p-8">
            <div className="flex flex-col items-center text-center">
              <span className="grid h-11 w-11 place-items-center rounded-xl border border-warning-border bg-warning-subtle text-warning" aria-hidden="true"><ShieldAlert className="h-5 w-5" /></span>
              <h1 id="change-password-title" className="mt-5 text-2xl font-semibold leading-8">Update access key</h1>
              <p className="mt-2 text-sm leading-6 text-text-muted">Your first sign-in requires a new access key before you can continue.</p>
            </div>

            <form onSubmit={handleSubmit} className="mt-8 flex flex-col gap-5">
              <div>
                <label htmlFor="new-access-key" className="text-sm font-medium text-text-muted">New access key</label>
                <input id="new-access-key" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required className="ui-field mt-2 font-mono" />
              </div>
              <div>
                <label htmlFor="confirm-access-key" className="text-sm font-medium text-text-muted">Confirm access key</label>
                <input id="confirm-access-key" type="password" autoComplete="new-password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required className="ui-field mt-2 font-mono" />
              </div>
              {error && <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{error}</p>}
              <button type="submit" className="ui-button ui-button-primary mt-2 w-full">Update and continue</button>
            </form>
          </div>
        </section>
      </div>
    </main>
  );
}

"use client";

import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Eye, EyeOff, KeyRound, ShieldCheck, UserRound } from "lucide-react";

function getSafeNextDestination() {
  const next = new URLSearchParams(window.location.search).get("next");
  if (!next || !next.startsWith("/") || next.startsWith("//")) return "/dashboard";
  return next;
}

export default function LoginForm() {
  const [operatorId, setOperatorId] = useState("");
  const [accessKey, setAccessKey] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAccessKeyVisible, setIsAccessKeyVisible] = useState(false);
  const submitButton = useRef<HTMLButtonElement>(null);
  const router = useRouter();

  const handleAuthenticate = async (event: React.FormEvent) => {
    event.preventDefault();
    if (isSubmitting) return;

    setError("");
    setIsSubmitting(true);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operatorId, password: accessKey }),
      });
      const data = await res.json();

      if (data.success) {
        router.push(data.isFirstLogin ? "/change-password" : getSafeNextDestination());
      } else {
        setError(data.error || "ACCESS DENIED: Invalid Credentials.");
      }
    } catch {
      setError("System Offline: Database Connection Failed.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <section aria-labelledby="login-title" className="pti-auth-card ui-panel w-full max-w-md">
      <div className="flex flex-col p-6 sm:p-8">
        <div className="flex items-center justify-between gap-4">
          <span className="grid h-11 w-11 place-items-center rounded-xl border border-primary-border bg-primary-subtle text-primary" aria-hidden="true"><ShieldCheck className="h-5 w-5" /></span>
          <span className="ui-badge border-primary-border bg-primary-subtle text-primary">Operator access</span>
        </div>

        <h1 id="login-title" className="mt-6 text-2xl font-semibold leading-8 text-text">Operator sign in</h1>
        <p className="mt-2 text-sm leading-6 text-text-muted">Use your authorized operator credentials to access the read-only workspace.</p>

        <form onSubmit={(event) => void handleAuthenticate(event)} className="mt-8 flex w-full flex-col gap-5" aria-busy={isSubmitting}>
          <div>
            <div className="mb-2 flex justify-between">
              <label htmlFor="operator-id" className="text-xs font-medium text-text-muted">OPERATOR ID</label>
              <span className="text-xs text-text-subtle">REQUIRED</span>
            </div>
            <div className="relative">
              <UserRound className="pointer-events-none absolute inset-y-0 left-4 my-auto h-4 w-4 text-text-subtle" aria-hidden="true" />
              <input
                id="operator-id"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "login-error" : undefined}
                type="text"
                placeholder="admin"
                value={operatorId}
                onChange={(event) => setOperatorId(event.target.value)}
                name="operatorId"
                autoComplete="username"
                className="ui-field pl-11 font-mono"
                disabled={isSubmitting}
                required
              />
            </div>
          </div>

          <div>
            <div className="mb-2 flex justify-between">
              <label htmlFor="access-key" className="text-xs font-medium text-text-muted">ACCESS KEY</label>
              <span className="text-xs text-text-subtle">ENCRYPTED</span>
            </div>
            <div className="relative">
              <KeyRound className="pointer-events-none absolute inset-y-0 left-4 my-auto h-4 w-4 text-text-subtle" aria-hidden="true" />
              <input
                id="access-key"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "login-error" : undefined}
                type={isAccessKeyVisible ? "text" : "password"}
                placeholder="admin"
                value={accessKey}
                onChange={(event) => setAccessKey(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Tab" && !event.shiftKey) {
                    event.preventDefault();
                    submitButton.current?.focus();
                  }
                }}
                name="accessKey"
                autoComplete="current-password"
                className="ui-field pl-11 pr-11 font-mono"
                disabled={isSubmitting}
                required
              />
              <button
                type="button"
                className="absolute inset-y-0 right-1 grid w-10 place-items-center rounded-md text-text-subtle transition-colors duration-150 hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus-ring"
                onClick={() => setIsAccessKeyVisible((visible) => !visible)}
                aria-label={isAccessKeyVisible ? "Hide access key" : "Show access key"}
                aria-pressed={isAccessKeyVisible}
                disabled={isSubmitting}
              >
                {isAccessKeyVisible ? <EyeOff className="h-4 w-4" aria-hidden="true" /> : <Eye className="h-4 w-4" aria-hidden="true" />}
              </button>
            </div>
          </div>

          {error && (
            <p id="login-error" role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{error}</p>
          )}

          <button ref={submitButton} type="submit" className="ui-button ui-button-primary mt-4 w-full" disabled={isSubmitting}>
            {isSubmitting ? "Authenticating…" : "Authenticate"}
            <ShieldCheck className="h-4 w-4" aria-hidden="true" />
          </button>
        </form>

        <div className="mt-8 flex flex-col gap-3 border-t border-border pt-5 text-center">
          <p className="text-sm text-text-muted">Need a reset? Contact your system administrator.</p>
          <p className="max-w-xs self-center text-xs leading-5 text-text-subtle">Unauthorized access attempts may be monitored and logged.</p>
        </div>
      </div>
    </section>
  );
}

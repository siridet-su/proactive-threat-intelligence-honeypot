"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginForm() {
  const [operatorId, setOperatorId] = useState("");
  const [accessKey, setAccessKey] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();

  const handleAuthenticate = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setError("");

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operatorId, password: accessKey }),
      });
      const data = await res.json();

      if (data.success) {
        // เก็บ Role ไว้ใน localStorage เพื่อใช้เช็คสิทธิ์ (จำลอง Session)
        localStorage.setItem("userRole", data.role);
        localStorage.setItem("operatorId", data.operatorId || operatorId);

        if (data.isFirstLogin) {
          router.push("/change-password"); // พาไปหน้าเปลี่ยนรหัส
        } else {
          router.push("/dashboard");
        }
      } else {
        setError(data.error || "ACCESS DENIED: Invalid Credentials.");
      }
    } catch (err) {
      setError("System Offline: Database Connection Failed.");
    }
  };

  return (
    <div className="ui-panel w-full max-w-md">
      <div className="p-6 sm:p-8 flex flex-col items-center">

        {/* Shield Icon */}
        <div className="mb-4 text-primary">
          <svg className="w-8 h-8" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-1.998A11.954 11.954 0 0110 1.944z" clipRule="evenodd" />
          </svg>
        </div>

        {/* Title */}
        <h1 className="text-2xl leading-8 text-text font-semibold mb-2">ACCESS CONTROL</h1>
        <p className="text-xs text-text-subtle font-mono mb-8">SECURE TERMINAL NODE: 0x8F-B22</p>

        <div className="w-full flex flex-col gap-5">

          {/* Operator ID Input */}
          <div>
            <div className="flex justify-between mb-2">
              <label htmlFor="operator-id" className="text-xs text-text-muted font-medium">OPERATOR ID</label>
              <span className="text-xs text-text-subtle">REQUIRED</span>
            </div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-text-subtle">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
              </div>
              <input
                id="operator-id"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "login-error" : undefined}
                type="text"
                placeholder="admin"
                value={operatorId}
                onChange={(e) => setOperatorId(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { e?.preventDefault(); void handleAuthenticate(); } }}
                className="ui-field pl-10 font-mono"
                required
              />
            </div>
          </div>

          {/* Access Key Input */}
          <div>
             <div className="flex justify-between mb-2">
              <label htmlFor="access-key" className="text-xs text-text-muted font-medium">ACCESS KEY</label>
              <span className="text-xs text-text-subtle">ENCRYPTED</span>
            </div>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-text-subtle">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>
              </div>
              <input
                id="access-key"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "login-error" : undefined}
                type="password"
                placeholder="admin"
                value={accessKey}
                onChange={(e) => setAccessKey(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { e?.preventDefault(); void handleAuthenticate(); } }}
                className="ui-field pl-10 font-mono"
                required
              />
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <p id="login-error" role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{error}</p>
          )}

          {/* Submit Button */}
          <button
            type="button"
            onClick={() => void handleAuthenticate()}
            className="ui-button ui-button-primary mt-4 w-full"
          >
            AUTHENTICATE
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          </button>

        </div>

        {/* Footer Warning */}
        <div className="mt-8 text-center flex flex-col gap-2">
          <a href="#" className="text-xs text-text-muted hover:text-primary">FORGOT ACCESS KEY?</a>
          <p className="text-xs text-text-subtle mt-4 max-w-xs leading-5">
            WARNING: UNAUTHORIZED ACCESS ATTEMPTS ARE MONITORED AND LOGGED. FEDERAL PROSECUTION MAY APPLY.
          </p>
          <a href="/dashboard" className="text-xs text-primary hover:underline mt-2">EMERGENCY BYPASS (DEV ONLY)</a>
        </div>

      </div>
    </div>
  );
}
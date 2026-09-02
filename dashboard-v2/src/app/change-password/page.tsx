"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert } from "lucide-react";

export default function ChangePasswordPage() {
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const router = useRouter();
  const [operatorId, setOperatorId] = useState("");

  useEffect(() => {
    const id = localStorage.getItem("operatorId");
    if (!id) router.push("/login");
    // eslint-disable-next-line react-hooks/set-state-in-effect
    else setOperatorId(id);
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match!");
      return;
    }
    
    const res = await fetch("/api/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operatorId, newPassword }),
    });

    if (res.ok) {
      alert("Password updated successfully. Access Granted.");
      router.push("/dashboard");
    } else {
      setError("Failed to update password.");
    }
  };

  return (
    <main className="min-h-screen bg-[#050507] flex items-center justify-center p-4">
      <div className="bg-[#0a0a0c] p-10 rounded-xl border border-purple-900/50 shadow-2xl max-w-md w-full">
        <div className="flex flex-col items-center mb-8">
          <ShieldAlert className="w-10 h-10 text-amber-500 mb-4" />
          <h2 className="text-xl text-white font-semibold">FIRST LOGIN DETECTED</h2>
          <p className="text-xs text-slate-400 mt-2 text-center">Security protocol requires you to update your default access key before proceeding.</p>
        </div>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div>
            <label className="text-xs text-slate-400 font-mono">NEW ACCESS KEY</label>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required className="w-full bg-[#111116] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
          </div>
          <div>
            <label className="text-xs text-slate-400 font-mono">CONFIRM ACCESS KEY</label>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required className="w-full bg-[#111116] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
          </div>
          {error && <p className="text-red-500 text-xs text-center">{error}</p>}
          <button type="submit" className="mt-4 w-full bg-purple-700 hover:bg-purple-600 text-white py-3 rounded text-sm font-bold tracking-widest transition-colors">
            UPDATE & PROCEED
          </button>
        </form>
      </div>
    </main>
  );
}
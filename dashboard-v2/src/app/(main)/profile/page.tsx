"use client";
import { useState, useEffect } from "react";
import { Settings, User, ShieldCheck, Key, Edit2, X, Info } from "lucide-react";
import { isDashboardUser } from "@/lib/dashboardTypes";
import type { DashboardProfile } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";

export default function ProfilePage() {
  const [user, setUser] = useState<DashboardProfile | null>(null);
  const [loading, setLoading] = useState(true);

  // Modals state
  const [isEditInfoOpen, setIsEditInfoOpen] = useState(false);
  const [isEditPasswordOpen, setIsEditPasswordOpen] = useState(false);

  // Forms state
  const [infoForm, setInfoForm] = useState({ fullName: "", email: "" });
  const [passwordForm, setPasswordForm] = useState({ newPassword: "", confirmPassword: "" });
  const [passwordError, setPasswordError] = useState("");

  const fetchProfile = async () => {
    const operatorId = localStorage.getItem("operatorId");
    if (!operatorId) {
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`/api/users/${operatorId}`);
      if (res.ok) {
        const data: unknown = await res.json();
        if (isDashboardUser(data)) {
          setUser(data);
          setInfoForm({ fullName: data.fullName, email: data.email });
        }
      }
    } catch {
      console.error("Failed to load profile");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchProfile();
  }, []);

  const handleInfoSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    const res = await fetch("/api/users", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        operatorId: user.operatorId,
        fullName: infoForm.fullName,
        email: infoForm.email,
        position: user.position, // ส่งค่าเดิมกลับไปเพื่อไม่ให้หาย
        role: user.role
      })
    });

    if (res.ok) {
      alert("Personal information updated.");
      setIsEditInfoOpen(false);
      fetchProfile();
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setPasswordError("Passwords do not match.");
      return;
    }

    const res = await fetch("/api/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operatorId: user.operatorId, newPassword: passwordForm.newPassword }),
    });

    if (res.ok) {
      alert("Security credentials updated successfully.");
      setIsEditPasswordOpen(false);
      setPasswordForm({ newPassword: "", confirmPassword: "" });
      setPasswordError("");
    }
  };

  if (loading) return <div className="min-h-[360px] py-16"><RegionState kind="loading" title="Loading profile" description="Retrieving operator account details." /></div>;
  if (!user) return <div className="min-h-[360px] py-16"><RegionState kind="error" title="Profile unavailable" description="The operator profile could not be loaded." /></div>;

  return (
    <div className="max-w-6xl space-y-7 pb-10">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border pb-6">
        <Settings className="h-6 w-6 text-primary" aria-hidden="true" />
        <h1 className="text-2xl font-semibold leading-8">User profile</h1>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left Column (Metadata) */}
        <div className="space-y-6 lg:col-span-1">
          <div className="ui-panel p-6">
            <h2 className="text-2xl font-semibold text-text">{user.fullName}</h2>
            <p className="mt-1 text-sm text-primary">{user.position}</p>

            <div className="mt-6 flex items-center gap-2 rounded-lg border border-border bg-surface-subtle p-3 font-mono text-xs text-text">
              <User className="h-4 w-4 text-text-subtle" aria-hidden="true" />
              OP-ID: {user.operatorId}
            </div>

            <div className="mt-8 flex items-center gap-2 border-b border-border pb-3 font-semibold text-text">
              <Info className="h-4 w-4 text-primary" aria-hidden="true" /> Account metadata
            </div>

            <div className="mt-5 space-y-4 text-sm">
              <div>
                <p className="mb-1 text-xs text-text-subtle">Account created</p>
                <p className="text-text">{user.createdAt ? new Date(user.createdAt).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) + ' UTC' : 'N/A'}</p>
              </div>
              <div>
                <p className="mb-1 text-xs text-text-subtle">Clearance level</p>
                <p className="flex items-center gap-2 text-text">
                  <span className={`h-2 w-2 rounded-full ${user.role === 'Admin' ? 'bg-primary' : 'bg-success'}`} aria-hidden="true"></span>
                  {user.role === 'Admin' ? 'Tier 4 (Admin)' : 'Tier 2 (Supporter)'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (Editable Info) */}
        <div className="space-y-6 lg:col-span-2">

          {/* Personal Information */}
          <div className="ui-panel p-6">
            <div className="mb-6 flex items-center justify-between gap-4 border-b border-border pb-4">
              <h3 className="flex items-center gap-2 text-base font-semibold text-text">
                <User className="h-5 w-5 text-primary" aria-hidden="true" /> Personal information
              </h3>
              <button onClick={() => setIsEditInfoOpen(true)} className="ui-button min-h-9 px-3 text-xs">
                <Edit2 className="h-3.5 w-3.5" aria-hidden="true" /> Edit information
              </button>
            </div>

            <div className="grid grid-cols-1 gap-6 text-sm sm:grid-cols-2">
              <div>
                <p className="mb-1 text-xs text-text-subtle">Full name</p>
                <p className="text-text">{user.fullName}</p>
              </div>
              <div>
                <p className="mb-1 text-xs text-text-subtle">Email address</p>
                <p className="break-all text-text">{user.email}</p>
              </div>
              <div>
                <p className="mb-1 text-xs text-text-subtle">Position</p>
                <p className="text-text">{user.position}</p>
              </div>
            </div>
          </div>

          {/* Security Controls */}
          <div className="ui-panel p-6">
            <div className="mb-6 border-b border-border pb-4">
              <h3 className="flex items-center gap-2 text-base font-semibold text-text">
                <ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" /> Security controls
              </h3>
            </div>

            <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
              <div>
                <h4 className="mb-1 text-sm font-semibold text-text">Authentication credentials</h4>
                <p className="text-sm text-text-muted">Update your access key regularly to maintain security.</p>
              </div>
              <button onClick={() => setIsEditPasswordOpen(true)} className="ui-button shrink-0 px-3 text-xs">
                <Key className="h-3.5 w-3.5" aria-hidden="true" /> Change password
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* Modal: Edit Personal Info */}
      {isEditInfoOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4">
          <div className="ui-panel w-full max-w-md p-6 shadow-[var(--shadow-raised)]">
            <div className="mb-6 flex items-center justify-between gap-4">
              <h3 className="text-lg font-semibold text-text">Edit personal information</h3>
              <button onClick={() => setIsEditInfoOpen(false)} className="ui-button min-h-9 px-2" aria-label="Close edit personal information"><X className="h-5 w-5"/></button>
            </div>
            <form onSubmit={handleInfoSubmit} className="space-y-4">
              <div>
                <label htmlFor="profile-full-name" className="text-sm font-medium text-text-muted">Full name</label>
                <input id="profile-full-name" type="text" value={infoForm.fullName} onChange={(e) => setInfoForm({...infoForm, fullName: e.target.value})} required className="ui-field mt-2" />
              </div>
              <div>
                <label htmlFor="profile-email" className="text-sm font-medium text-text-muted">Email</label>
                <input id="profile-email" type="email" value={infoForm.email} onChange={(e) => setInfoForm({...infoForm, email: e.target.value})} required className="ui-field mt-2" />
              </div>
              <button type="submit" className="ui-button ui-button-primary mt-4 w-full">
                Save changes
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Change Password */}
      {isEditPasswordOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4">
          <div className="ui-panel w-full max-w-md p-6 shadow-[var(--shadow-raised)]">
            <div className="mb-6 flex items-center justify-between gap-4">
              <h3 className="text-lg font-semibold text-text">Change password</h3>
              <button onClick={() => setIsEditPasswordOpen(false)} className="ui-button min-h-9 px-2" aria-label="Close change password dialog"><X className="h-5 w-5"/></button>
            </div>
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <div>
                <label htmlFor="profile-new-password" className="text-sm font-medium text-text-muted">New password</label>
                <input id="profile-new-password" type="password" autoComplete="new-password" value={passwordForm.newPassword} onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})} required className="ui-field mt-2" />
              </div>
              <div>
                <label htmlFor="profile-confirm-password" className="text-sm font-medium text-text-muted">Confirm password</label>
                <input id="profile-confirm-password" type="password" autoComplete="new-password" value={passwordForm.confirmPassword} onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})} required className="ui-field mt-2" />
              </div>
              {passwordError && <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{passwordError}</p>}
              <button type="submit" className="ui-button ui-button-primary mt-4 w-full">
                Update credentials
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

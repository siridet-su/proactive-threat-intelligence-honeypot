"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import { Settings, User, ShieldCheck, Key, Edit2, X, Info, LoaderCircle } from "lucide-react";
import { isDashboardUser } from "@/lib/dashboardTypes";
import type { DashboardProfile } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";
import { OperationToast, type OperationToastKind } from "@/components/ui/OperationToast";
import { useModalFocusTrap } from "@/lib/useModalFocusTrap";

type OperationNotice = {
  kind: OperationToastKind;
  title: string;
  description: string;
};

async function getRequestError(response: Response, fallback: string) {
  const payload: unknown = await response.json().catch(() => null);
  if (payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string") return payload.error;
  return fallback;
}

export default function ProfilePage() {
  const [user, setUser] = useState<DashboardProfile | null>(null);
  const [loading, setLoading] = useState(true);

  // Modals state
  const [isEditInfoOpen, setIsEditInfoOpen] = useState(false);
  const [isEditInfoPresent, setIsEditInfoPresent] = useState(false);
  const [isEditPasswordOpen, setIsEditPasswordOpen] = useState(false);
  const [isEditPasswordPresent, setIsEditPasswordPresent] = useState(false);

  // Forms state
  const [infoForm, setInfoForm] = useState({ fullName: "", email: "" });
  const [passwordForm, setPasswordForm] = useState({ newPassword: "", confirmPassword: "" });
  const [infoError, setInfoError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [isSavingInfo, setIsSavingInfo] = useState(false);
  const [isSavingPassword, setIsSavingPassword] = useState(false);
  const [operationNotice, setOperationNotice] = useState<OperationNotice | null>(null);
  const operationNoticeTimer = useRef<number | null>(null);
  const editInfoCloseTimer = useRef<number | null>(null);
  const editPasswordCloseTimer = useRef<number | null>(null);
  const editInfoDialogRef = useRef<HTMLElement | null>(null);
  const editPasswordDialogRef = useRef<HTMLElement | null>(null);

  useModalFocusTrap(isEditInfoOpen, editInfoDialogRef);
  useModalFocusTrap(isEditPasswordOpen, editPasswordDialogRef);

  useEffect(() => () => {
    if (operationNoticeTimer.current !== null) window.clearTimeout(operationNoticeTimer.current);
    if (editInfoCloseTimer.current !== null) window.clearTimeout(editInfoCloseTimer.current);
    if (editPasswordCloseTimer.current !== null) window.clearTimeout(editPasswordCloseTimer.current);
  }, []);

  const openEditInfo = () => {
    if (editInfoCloseTimer.current !== null) window.clearTimeout(editInfoCloseTimer.current);
    setInfoError("");
    setIsEditInfoPresent(true);
    window.requestAnimationFrame(() => setIsEditInfoOpen(true));
  };

  const closeEditInfo = useCallback(() => {
    if (isSavingInfo) return;
    setIsEditInfoOpen(false);
    if (editInfoCloseTimer.current !== null) window.clearTimeout(editInfoCloseTimer.current);
    editInfoCloseTimer.current = window.setTimeout(() => setIsEditInfoPresent(false), 180);
  }, [isSavingInfo]);

  const openEditPassword = () => {
    if (editPasswordCloseTimer.current !== null) window.clearTimeout(editPasswordCloseTimer.current);
    setPasswordError("");
    setPasswordForm({ newPassword: "", confirmPassword: "" });
    setIsEditPasswordPresent(true);
    window.requestAnimationFrame(() => setIsEditPasswordOpen(true));
  };

  const closeEditPassword = useCallback(() => {
    if (isSavingPassword) return;
    setIsEditPasswordOpen(false);
    if (editPasswordCloseTimer.current !== null) window.clearTimeout(editPasswordCloseTimer.current);
    editPasswordCloseTimer.current = window.setTimeout(() => setIsEditPasswordPresent(false), 180);
  }, [isSavingPassword]);

  useEffect(() => {
    if (!isEditInfoPresent && !isEditPasswordPresent) return;
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (isEditInfoPresent && !isSavingInfo) closeEditInfo();
        if (isEditPasswordPresent && !isSavingPassword) closeEditPassword();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [isEditInfoPresent, isEditPasswordPresent, isSavingInfo, isSavingPassword, closeEditInfo, closeEditPassword]);

  const showOperationNotice = (notice: OperationNotice) => {
    if (operationNoticeTimer.current !== null) window.clearTimeout(operationNoticeTimer.current);
    setOperationNotice(notice);
    operationNoticeTimer.current = window.setTimeout(() => {
      setOperationNotice(null);
      operationNoticeTimer.current = null;
    }, 4800);
  };

  const dismissOperationNotice = () => {
    if (operationNoticeTimer.current !== null) window.clearTimeout(operationNoticeTimer.current);
    operationNoticeTimer.current = null;
    setOperationNotice(null);
  };

  const fetchProfile = async () => {
    try {
      const sessionResponse = await fetch("/api/auth/session", { cache: "no-store" });
      if (!sessionResponse.ok) throw new Error("Session unavailable");
      const session: unknown = await sessionResponse.json();
      if (!session || typeof session !== "object" || typeof (session as { operatorId?: unknown }).operatorId !== "string") {
        throw new Error("Session unavailable");
      }
      const operatorId = (session as { operatorId: string }).operatorId;
      const res = await fetch(`/api/users/${operatorId}`);
      if (res.ok) {
        const data: unknown = await res.json();
        if (isDashboardUser(data)) {
          setUser(data);
          setInfoForm({ fullName: data.fullName, email: data.email });
        }
      }
    } catch {
      setUser(null);
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
    if (!user || isSavingInfo) return;
    setInfoError("");
    setIsSavingInfo(true);

    try {
      const res = await fetch("/api/users", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          operatorId: user.operatorId,
          fullName: infoForm.fullName,
          email: infoForm.email,
          position: user.position,
          role: user.role,
        }),
      });
      if (!res.ok) throw new Error(await getRequestError(res, "Personal information could not be updated."));
      closeEditInfo();
      void fetchProfile();
      showOperationNotice({ kind: "success", title: "Profile updated", description: "Personal information was saved successfully." });
    } catch (error) {
      setInfoError(error instanceof Error ? error.message : "Personal information could not be updated. Please try again.");
    } finally {
      setIsSavingInfo(false);
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user || isSavingPassword) return;
    setPasswordError("");
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      setPasswordError("Passwords do not match.");
      return;
    }
    setIsSavingPassword(true);

    try {
      const res = await fetch("/api/auth/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operatorId: user.operatorId, newPassword: passwordForm.newPassword }),
      });
      if (!res.ok) throw new Error(await getRequestError(res, "Security credentials could not be updated."));
      closeEditPassword();
      setPasswordForm({ newPassword: "", confirmPassword: "" });
      showOperationNotice({ kind: "success", title: "Credentials updated", description: "Your access key was updated successfully." });
    } catch (error) {
      setPasswordError(error instanceof Error ? error.message : "Security credentials could not be updated. Please try again.");
    } finally {
      setIsSavingPassword(false);
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
                <div className="mt-1">
                  <span className={`ui-badge ${user.role === 'Admin' ? 'border-primary-border bg-primary-subtle text-primary' : 'border-neutral-border bg-neutral-subtle text-text-muted'}`}>
                    <span className={`h-2 w-2 rounded-full ${user.role === 'Admin' ? 'bg-primary' : 'bg-neutral'}`} aria-hidden="true" />
                    {user.role === 'Admin' ? 'Level 4 (Admin)' : 'Level 2 (Supporter)'}
                  </span>
                </div>
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
              <button onClick={openEditInfo} className="ui-button min-h-9 px-3 text-xs">
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
              <button onClick={openEditPassword} className="ui-button shrink-0 px-3 text-xs">
                <Key className="h-3.5 w-3.5" aria-hidden="true" /> Change password
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* Modal: Edit Personal Info */}
      {isEditInfoPresent && (
        <div data-open={isEditInfoOpen} onClick={(e) => { if (e.target === e.currentTarget && !isSavingInfo) closeEditInfo(); }} className="pti-modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4" role="presentation">
          <section ref={editInfoDialogRef} data-open={isEditInfoOpen} className="pti-modal-panel ui-panel w-full max-w-md p-6 shadow-[var(--shadow-raised)]" role="dialog" aria-modal="true" aria-labelledby="edit-personal-title" tabIndex={-1}>
            <div className="mb-6 flex items-center justify-between gap-4">
              <h3 id="edit-personal-title" className="text-lg font-semibold text-text">Edit personal information</h3>
              <button onClick={closeEditInfo} className="ui-button min-h-9 px-2" aria-label="Close edit personal information" disabled={isSavingInfo}><X className="h-5 w-5"/></button>
            </div>
            <form onSubmit={handleInfoSubmit} className="space-y-4" aria-busy={isSavingInfo}>
              <div>
                <label htmlFor="profile-full-name" className="text-sm font-medium text-text-muted">Full name</label>
                <input id="profile-full-name" type="text" value={infoForm.fullName} onChange={(e) => setInfoForm({...infoForm, fullName: e.target.value})} required className="ui-field mt-2" disabled={isSavingInfo} data-autofocus />
              </div>
              <div>
                <label htmlFor="profile-email" className="text-sm font-medium text-text-muted">Email</label>
                <input id="profile-email" type="email" value={infoForm.email} onChange={(e) => setInfoForm({...infoForm, email: e.target.value})} required className="ui-field mt-2" disabled={isSavingInfo} />
              </div>
              {infoError && <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{infoError}</p>}
              <button type="submit" className="ui-button ui-button-primary mt-4 w-full" disabled={isSavingInfo}>
                {isSavingInfo && <LoaderCircle className="h-4 w-4 motion-safe:animate-spin" aria-hidden="true" />}
                {isSavingInfo ? "Saving changes…" : "Save changes"}
              </button>
            </form>
          </section>
        </div>
      )}

      {/* Modal: Change Password */}
      {isEditPasswordPresent && (
        <div data-open={isEditPasswordOpen} onClick={(e) => { if (e.target === e.currentTarget && !isSavingPassword) closeEditPassword(); }} className="pti-modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4" role="presentation">
          <section ref={editPasswordDialogRef} data-open={isEditPasswordOpen} className="pti-modal-panel ui-panel w-full max-w-md p-6 shadow-[var(--shadow-raised)]" role="dialog" aria-modal="true" aria-labelledby="change-password-title" tabIndex={-1}>
            <div className="mb-6 flex items-center justify-between gap-4">
              <h3 id="change-password-title" className="text-lg font-semibold text-text">Change password</h3>
              <button onClick={closeEditPassword} className="ui-button min-h-9 px-2" aria-label="Close change password dialog" disabled={isSavingPassword}><X className="h-5 w-5"/></button>
            </div>
            <form onSubmit={handlePasswordSubmit} className="space-y-4" aria-busy={isSavingPassword}>
              <div>
                <label htmlFor="profile-new-password" className="text-sm font-medium text-text-muted">New password</label>
                <input id="profile-new-password" type="password" autoComplete="new-password" value={passwordForm.newPassword} onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})} required className="ui-field mt-2" disabled={isSavingPassword} data-autofocus />
              </div>
              <div>
                <label htmlFor="profile-confirm-password" className="text-sm font-medium text-text-muted">Confirm password</label>
                <input id="profile-confirm-password" type="password" autoComplete="new-password" value={passwordForm.confirmPassword} onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})} required className="ui-field mt-2" disabled={isSavingPassword} />
              </div>
              {passwordError && <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{passwordError}</p>}
              <button type="submit" className="ui-button ui-button-primary mt-4 w-full" disabled={isSavingPassword}>
                {isSavingPassword && <LoaderCircle className="h-4 w-4 motion-safe:animate-spin" aria-hidden="true" />}
                {isSavingPassword ? "Updating credentials…" : "Update credentials"}
              </button>
            </form>
          </section>
        </div>
      )}
      {operationNotice && <OperationToast {...operationNotice} onDismiss={dismissOperationNotice} />}
    </div>
  );
}

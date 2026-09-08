"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import Link from "next/link";
import { Briefcase, CheckCircle2, Edit2, KeyRound, LoaderCircle, Lock, ShieldCheck, ShieldX, UserPlus, X } from "lucide-react";
import { isDashboardUser } from "@/lib/dashboardTypes";
import type { DashboardUser } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";
import { SelectMenu } from "@/components/ui/SelectMenu";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
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

export default function UserManagementPage() {
  const [users, setUsers] = useState<DashboardUser[]>([]);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isAddModalPresent, setIsAddModalPresent] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isEditModalPresent, setIsEditModalPresent] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);
  const [currentUserId, setCurrentUserId] = useState("");
  const [currentUserRole, setCurrentUserRole] = useState("");

  const [formData, setFormData] = useState({ fullName: "", email: "", position: "Lead Sentinel", role: "Supporter", initialPassword: "" });
  const [createError, setCreateError] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [createdOperatorId, setCreatedOperatorId] = useState("");
  const [isSavingEdit, setIsSavingEdit] = useState(false);
  const [editError, setEditError] = useState("");
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [operationNotice, setOperationNotice] = useState<OperationNotice | null>(null);

  // State สำหรับแก้ไขข้อมูล
  const [editFormData, setEditFormData] = useState({ operatorId: "", fullName: "", email: "", position: "", role: "", newPassword: "" });
  const createDialogCloseTimer = useRef<number | null>(null);
  const editDialogCloseTimer = useRef<number | null>(null);
  const operationNoticeTimer = useRef<number | null>(null);
  const createOperatorDialogRef = useRef<HTMLElement | null>(null);
  const editOperatorDialogRef = useRef<HTMLDivElement | null>(null);
  const [deleteCandidate, setDeleteCandidate] = useState<DashboardUser | null>(null);

  useModalFocusTrap(isAddModalOpen, createOperatorDialogRef);
  useModalFocusTrap(isEditModalOpen, editOperatorDialogRef);

  useEffect(() => () => {
    if (createDialogCloseTimer.current !== null) window.clearTimeout(createDialogCloseTimer.current);
    if (editDialogCloseTimer.current !== null) window.clearTimeout(editDialogCloseTimer.current);
    if (operationNoticeTimer.current !== null) window.clearTimeout(operationNoticeTimer.current);
  }, []);

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

  useEffect(() => {
    const loadSession = async () => {
      try {
        const response = await fetch("/api/auth/session", { cache: "no-store" });
        if (!response.ok) return;
        const data: unknown = await response.json();
        if (!data || typeof data !== "object") return;
        const session = data as { operatorId?: unknown; role?: unknown };
        if (typeof session.operatorId === "string") setCurrentUserId(session.operatorId);
        if (typeof session.role === "string") setCurrentUserRole(session.role);
      } catch {
        // The server-side route guard remains authoritative.
      }
    };
    void loadSession();
  }, []);

  useEffect(() => {
    const loadUsers = async () => {
      try {
        const res = await fetch("/api/users");
        if (!res.ok) throw new Error("User request failed");
        const data: unknown = await res.json();
        if (!Array.isArray(data)) throw new Error("User response unavailable");
        setUsers(data.filter(isDashboardUser));
        setFetchFailed(false);
      } catch {
        setFetchFailed(true);
      } finally {
        setLoading(false);
      }
    };
    loadUsers();
  }, [refreshKey]);

  // ฟังก์ชันเพิ่มผู้ใช้
  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isCreating) return;
    setCreateError("");
    setIsCreating(true);

    try {
      const res = await fetch("/api/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });
      const data: unknown = await res.json();
      if (!res.ok || !data || typeof data !== "object") {
        const message = data && typeof data === "object" && "error" in data && typeof data.error === "string"
          ? data.error
          : "The operator account could not be created.";
        setCreateError(message);
        return;
      }

      const candidate = data as { user?: { operatorId?: unknown } };
      setCreatedOperatorId(typeof candidate.user?.operatorId === "string" ? candidate.user.operatorId : "New operator");
      setRefreshKey((previous) => previous + 1);
    } catch {
      setCreateError("The operator account could not be created. Please try again.");
    } finally {
      setIsCreating(false);
    }
  };

  const openCreateOperator = () => {
    if (createDialogCloseTimer.current !== null) window.clearTimeout(createDialogCloseTimer.current);
    setCreateError("");
    setCreatedOperatorId("");
    setFormData({ fullName: "", email: "", position: "Lead Sentinel", role: "Supporter", initialPassword: "" });
    setIsAddModalPresent(true);
    window.requestAnimationFrame(() => setIsAddModalOpen(true));
  };

  const closeCreateOperator = useCallback(() => {
    if (isCreating) return;
    setIsAddModalOpen(false);
    if (createDialogCloseTimer.current !== null) window.clearTimeout(createDialogCloseTimer.current);
    createDialogCloseTimer.current = window.setTimeout(() => setIsAddModalPresent(false), 180);
    setCreateError("");
    setCreatedOperatorId("");
  }, [isCreating]);

  // ฟังก์ชันเปิดหน้าแก้ไข
  const openEditModal = (user: DashboardUser) => {
    if (editDialogCloseTimer.current !== null) window.clearTimeout(editDialogCloseTimer.current);
    setEditError("");
    setEditFormData({ ...user, newPassword: "" });
    setIsEditModalPresent(true);
    window.requestAnimationFrame(() => setIsEditModalOpen(true));
  };

  const closeEditModal = useCallback((force = false) => {
    if (isSavingEdit && !force) return;
    setIsEditModalOpen(false);
    if (editDialogCloseTimer.current !== null) window.clearTimeout(editDialogCloseTimer.current);
    editDialogCloseTimer.current = window.setTimeout(() => setIsEditModalPresent(false), 180);
  }, [isSavingEdit]);

  useEffect(() => {
    if (!isAddModalPresent && !isEditModalPresent) return;
    const oldOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (isAddModalPresent && !isCreating) closeCreateOperator();
        if (isEditModalPresent && !isSavingEdit) closeEditModal();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = oldOverflow;
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [isAddModalPresent, isEditModalPresent, isCreating, isSavingEdit, closeCreateOperator, closeEditModal]);

  // ฟังก์ชันบันทึกการแก้ไข
  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSavingEdit) return;
    setEditError("");
    setIsSavingEdit(true);
    let profileSaved = false;

    try {
      const profileResponse = await fetch("/api/users", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editFormData),
      });
      if (!profileResponse.ok) throw new Error(await getRequestError(profileResponse, "The operator profile could not be updated."));
      profileSaved = true;

      const passwordChanged = Boolean(editFormData.newPassword && editFormData.operatorId === currentUserId);
      if (passwordChanged) {
        const passwordResponse = await fetch("/api/auth/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ operatorId: editFormData.operatorId, newPassword: editFormData.newPassword }),
        });
        if (!passwordResponse.ok) throw new Error(await getRequestError(passwordResponse, "The access key could not be updated."));
      }

      closeEditModal(true);
      setRefreshKey((previous) => previous + 1);
      showOperationNotice({
        kind: "success",
        title: "Operator updated",
        description: passwordChanged ? "Profile and access key were saved successfully." : "Profile changes were saved successfully.",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "The operator profile could not be updated. Please try again.";
      if (profileSaved) {
        setRefreshKey((previous) => previous + 1);
        setEditError(`Profile changes were saved, but ${message.charAt(0).toLowerCase()}${message.slice(1)}`);
      } else {
        setEditError(message);
      }
    } finally {
      setIsSavingEdit(false);
    }
  };

  // ฟังก์ชันลบผู้ใช้
  const requestDelete = (user: DashboardUser) => {
    if (user.operatorId === currentUserId) return;
    setDeleteError("");
    setDeleteCandidate(user);
  };

  const confirmDelete = async () => {
    if (!deleteCandidate || isDeleting) return;
    const operatorId = deleteCandidate.operatorId;
    setDeleteError("");
    setIsDeleting(true);
    try {
      const res = await fetch("/api/users", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operatorId })
      });
      if (!res.ok) throw new Error(await getRequestError(res, "The operator could not be removed."));
      setRefreshKey((previous) => previous + 1);
      setDeleteCandidate(null);
      showOperationNotice({ kind: "success", title: "Operator removed", description: `${operatorId} no longer has workspace access.` });
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : "The operator could not be removed. Please try again.");
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="space-y-6 pb-8">
      {/* Header (แสดงปุ่ม Add เฉพาะ Admin) */}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <h1 className="text-2xl font-semibold">User management</h1>
          <p className="mt-2 text-sm text-text-muted">Manage operator access permissions and security clearances.</p>
        </div>
        <div className="flex flex-wrap gap-3">
          {currentUserRole === "Admin" && (
            <>
              <Link href="/user-management/positions" className="ui-button">
                <Briefcase className="w-4 h-4" /> Manage Positions
              </Link>
              <button onClick={openCreateOperator} className="ui-button ui-button-primary">
                <UserPlus className="w-4 h-4" /> Add New Operator
              </button>
            </>
          )}
        </div>
      </div>

      {/* Table Section */}
      <div className="ui-panel mt-8 overflow-hidden">
        <div className="flex items-center justify-between border-b border-border bg-surface-subtle p-5 sm:p-6">
          <h2 className="text-base font-semibold">Active operator roster</h2>
        </div>

        <div className="ui-scroll-region">
        <table className="ui-table min-w-[860px]">
          <thead>
            <tr>
              <th scope="col">OPERATOR ID</th>
              <th scope="col">FULL NAME</th>
              <th scope="col">POSITION</th>
              <th scope="col">ROLE</th>
              <th scope="col">STATUS</th>
              <th scope="col" className="text-right">ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {loading && Array.from({ length: 5 }, (_, index) => (
              <tr key={`user-loading-${index}`} aria-hidden="true">
                {Array.from({ length: 6 }, (_, column) => <td key={column}><div className="ui-skeleton h-4 w-full" /></td>)}
              </tr>
            ))}
            {!loading && fetchFailed && <tr><td colSpan={6} className="p-4"><RegionState kind="error" title="Operator roster unavailable" description="The user directory could not be loaded." /></td></tr>}
            {!loading && !fetchFailed && users.length === 0 && <tr><td colSpan={6} className="p-4"><RegionState kind="empty" title="No operators" description="No operator accounts were returned in the last successful response." /></td></tr>}
            {!loading && !fetchFailed && users.map((user, i) => {
              // เช็คสิทธิ์: เป็น Admin หรือเป็นตัวเอง
              const canEdit = currentUserRole === "Admin" || user.operatorId === currentUserId;
              const canDelete = currentUserRole === "Admin" && user.operatorId !== currentUserId;

              return (
                <tr key={i}>
                  <td className="font-mono text-sm font-medium text-primary">
                    {user.operatorId} {user.operatorId === currentUserId && <span className="ml-1 text-xs text-text-subtle">(YOU)</span>}
                  </td>
                  <td className="text-text">{user.fullName}</td>
                  <td className="text-text-muted">{user.position}</td><td className="text-text-muted">{user.role}</td>
                  <td>
                    <span className={`ui-badge ${user.status === "Active" ? "border-success-border bg-success-subtle text-success" : "border-danger-border bg-danger-subtle text-danger"}`}>
                      <span className={`h-2 w-2 rounded-full ${user.status === 'Active' ? 'bg-success' : 'bg-danger'}`} aria-hidden="true"></span>
                      {user.status}
                    </span>
                  </td>
                  <td className="text-right">
                    <div className="flex justify-end gap-2">
                    {canEdit && (
                       <button onClick={() => openEditModal(user)} className="ui-button min-h-9 px-2" aria-label={`Edit ${user.operatorId}`}><Edit2 className="h-4 w-4" aria-hidden="true" /></button>
                    )}
                    {canDelete && (
                       <button onClick={() => requestDelete(user)} className="ui-button min-h-9 px-2 text-danger" aria-label={`Delete ${user.operatorId}`}><ShieldX className="h-4 w-4" aria-hidden="true" /></button>
                    )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        </div>
      </div>

      {isAddModalPresent && (
        <div data-open={isAddModalOpen} onClick={(e) => { if (e.target === e.currentTarget && !isCreating) closeCreateOperator(); }} className="pti-modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4" role="presentation">
          <section ref={createOperatorDialogRef} data-open={isAddModalOpen} className="pti-modal-panel w-full max-w-xl overflow-hidden rounded-2xl border border-primary-border bg-surface shadow-[var(--shadow-raised)]" role="dialog" aria-modal="true" aria-labelledby="create-operator-title" tabIndex={-1}>
            <header className="flex items-start justify-between gap-4 border-b border-border bg-surface-subtle p-5 sm:p-6">
              <div className="flex gap-3">
                <span className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-primary-border bg-primary-subtle text-primary" aria-hidden="true"><ShieldCheck className="h-5 w-5" /></span>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-[0.14em] text-primary">Admin onboarding</p>
                  <h2 id="create-operator-title" className="mt-1 text-lg font-semibold">Create operator</h2>
                  <p className="mt-1 text-sm text-text-muted">Provision an account for the read-only intelligence workspace.</p>
                </div>
              </div>
              <button onClick={closeCreateOperator} className="ui-button min-h-9 px-2" aria-label="Close create operator dialog" disabled={isCreating}><X className="h-5 w-5" /></button>
            </header>

            {createdOperatorId ? (
              <div className="p-5 sm:p-6">
                <div className="rounded-xl border border-success-border bg-success-subtle p-5 text-center">
                  <CheckCircle2 className="mx-auto h-7 w-7 text-success" aria-hidden="true" />
                  <h3 className="mt-3 text-base font-semibold text-text">Operator created</h3>
                  <p className="mt-2 text-sm text-text-muted">Assigned operator ID</p>
                  <p className="mt-1 font-mono text-lg font-semibold text-primary">{createdOperatorId}</p>
                  <p className="mx-auto mt-4 max-w-sm text-sm leading-6 text-text-muted">Share the temporary access key through an approved secure channel. The operator will be required to change it at first sign-in.</p>
                </div>
                <button type="button" className="ui-button ui-button-primary mt-5 w-full" onClick={closeCreateOperator}>Done</button>
              </div>
            ) : (
              <form onSubmit={handleAddUser} className="grid gap-5 p-5 sm:grid-cols-2 sm:p-6" aria-busy={isCreating}>
                <div className="sm:col-span-2">
                  <label htmlFor="create-full-name" className="text-xs font-medium text-text-muted">Full name</label>
                  <input id="create-full-name" type="text" value={formData.fullName} onChange={(event) => setFormData({ ...formData, fullName: event.target.value })} required className="ui-field mt-1" disabled={isCreating} data-autofocus />
                </div>
                <div className="sm:col-span-2">
                  <label htmlFor="create-email" className="text-xs font-medium text-text-muted">Email</label>
                  <input id="create-email" type="email" value={formData.email} onChange={(event) => setFormData({ ...formData, email: event.target.value })} required className="ui-field mt-1" disabled={isCreating} />
                </div>
                <div>
                  <label htmlFor="create-position" className="text-xs font-medium text-text-muted">Position</label>
                  <SelectMenu id="create-position" value={formData.position} onValueChange={(position) => setFormData({ ...formData, position })} options={["Lead Sentinel", "Data Guardian", "Network Shield", "Threat Hunter"]} className="mt-1" disabled={isCreating} />
                </div>
                <div>
                  <label htmlFor="create-role" className="text-xs font-medium text-text-muted">Role</label>
                  <SelectMenu id="create-role" value={formData.role} onValueChange={(role) => setFormData({ ...formData, role })} options={["Supporter", "Admin"]} className="mt-1" disabled={isCreating} />
                </div>
                <div className="sm:col-span-2">
                  <div className="flex items-center justify-between gap-3">
                    <label htmlFor="create-access-key" className="text-xs font-medium text-text-muted">Temporary access key</label>
                    <span className="text-xs text-text-subtle">At least 8 characters</span>
                  </div>
                  <div className="relative mt-1">
                    <KeyRound className="pointer-events-none absolute inset-y-0 left-4 my-auto h-4 w-4 text-text-subtle" aria-hidden="true" />
                    <input id="create-access-key" type="password" value={formData.initialPassword} onChange={(event) => setFormData({ ...formData, initialPassword: event.target.value })} minLength={8} required className="ui-field pl-11 font-mono" autoComplete="new-password" disabled={isCreating} />
                  </div>
                  <p className="mt-2 text-xs leading-5 text-text-subtle">The operator must change this key on their first sign-in.</p>
                </div>
                {createError && <p role="alert" className="sm:col-span-2 rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{createError}</p>}
                <div className="flex flex-col-reverse gap-3 border-t border-border pt-5 sm:col-span-2 sm:flex-row sm:justify-end">
                  <button type="button" className="ui-button" onClick={closeCreateOperator} disabled={isCreating}>Cancel</button>
                  <button type="submit" className="ui-button ui-button-primary" disabled={isCreating}><UserPlus className="h-4 w-4" aria-hidden="true" />{isCreating ? "Creating operator…" : "Create operator"}</button>
                </div>
              </form>
            )}
          </section>
        </div>
      )}

      {/* Modal Edit User */}
      {isEditModalPresent && (
        <div data-open={isEditModalOpen} onClick={(e) => { if (e.target === e.currentTarget && !isSavingEdit) closeEditModal(); }} className="pti-modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4" role="presentation">
          <div ref={editOperatorDialogRef} data-open={isEditModalOpen} className="pti-modal-panel max-h-[90vh] w-full max-w-md overflow-y-auto rounded-2xl border border-border bg-surface p-6 shadow-[var(--shadow-raised)]" role="dialog" aria-modal="true" aria-labelledby="edit-operator-title" tabIndex={-1}>
            <div className="flex justify-between items-center mb-6">
              <h3 id="edit-operator-title" className="flex items-center gap-2 text-lg font-semibold"><Edit2 className="w-5 h-5 text-primary"/> Edit operator [{editFormData.operatorId}]
              </h3>
              <button onClick={() => closeEditModal()} className="ui-button min-h-9 px-2" aria-label="Close edit operator dialog" disabled={isSavingEdit}><X className="w-5 h-5"/></button>
            </div>

            <form onSubmit={handleEditSubmit} className="space-y-4" aria-busy={isSavingEdit}>
              <div>
                <label className="text-xs font-medium text-text-muted">Full name</label><input type="text" value={editFormData.fullName} onChange={(e) => setEditFormData({...editFormData, fullName: e.target.value})} required className="ui-field mt-1" disabled={isSavingEdit} data-autofocus />
              </div>
              <div>
                <label className="text-xs font-medium text-text-muted">Email</label><input type="email" value={editFormData.email} onChange={(e) => setEditFormData({...editFormData, email: e.target.value})} required className="ui-field mt-1" disabled={isSavingEdit} />
              </div>

              {/* ให้ Admin เท่านั้นที่เปลี่ยนตำแหน่งและ Role ได้ */}
              <div>
                <label className="text-xs font-medium text-text-muted">Position</label><SelectMenu value={editFormData.position} onValueChange={(position) => setEditFormData({...editFormData, position})} options={["Lead Sentinel", "Data Guardian", "Network Shield", "Threat Hunter"]} className="mt-1" disabled={isSavingEdit || currentUserRole !== "Admin"} />
              </div>
              <div>
                <label className="text-xs font-medium text-text-muted">Role</label><SelectMenu value={editFormData.role} onValueChange={(role) => setEditFormData({...editFormData, role})} options={["Admin", "Supporter"]} className="mt-1" disabled={isSavingEdit || currentUserRole !== "Admin"} />
              </div>

              {/* ส่วนเปลี่ยนรหัสผ่าน (แสดงเฉพาะตอนแก้ไขบัญชีตัวเอง) */}
              {editFormData.operatorId === currentUserId && (
                <div className="mt-4 border-t border-border pt-4"><label className="mb-2 flex items-center gap-1 text-xs font-medium text-warning">
                    <Lock className="w-3 h-3"/> CHANGE PASSWORD (OPTIONAL)
                  </label>
                  <input type="password" placeholder="Leave blank to keep current password" value={editFormData.newPassword} onChange={(e) => setEditFormData({...editFormData, newPassword: e.target.value})} className="ui-field" disabled={isSavingEdit} />
                </div>
              )}

              {editError && <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">{editError}</p>}
              <button type="submit" className="ui-button ui-button-primary mt-4 w-full" disabled={isSavingEdit}>
                {isSavingEdit && <LoaderCircle className="h-4 w-4 motion-safe:animate-spin" aria-hidden="true" />}
                {isSavingEdit ? "Saving changes…" : "Save changes"}
              </button>
            </form>
          </div>
        </div>
      )}
      <ConfirmDialog
        open={Boolean(deleteCandidate)}
        onOpenChange={(open) => { if (!open) setDeleteCandidate(null); }}
        onConfirm={() => void confirmDelete()}
        title="Remove operator access?"
        description={deleteCandidate ? `This will remove ${deleteCandidate.fullName || deleteCandidate.operatorId} from the operator roster. This action cannot be undone.` : ""}
        confirmLabel="Remove operator"
        confirmVariant="danger"
        isProcessing={isDeleting}
        processingLabel="Removing operator…"
        errorMessage={deleteError}
      />
      {operationNotice && <OperationToast {...operationNotice} onDismiss={dismissOperationNotice} />}
    </div>
  );
}

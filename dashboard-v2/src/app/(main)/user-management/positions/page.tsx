"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  Briefcase,
  Cpu,
  Database,
  Edit2,
  Info,
  Key,
  Lock,
  Network,
  Plus,
  Shield,
  Target,
  Terminal,
  Trash2,
  Users,
  X,
} from "lucide-react";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { OperationToast, type OperationToastKind } from "@/components/ui/OperationToast";
import { RegionState } from "@/components/ui/RegionState";
import { SelectMenu } from "@/components/ui/SelectMenu";
import type { JobPosition } from "@/lib/dashboardTypes";
import { useModalFocusTrap } from "@/lib/useModalFocusTrap";

const AVAILABLE_ICONS = [
  { name: "Shield", label: "Shield", Icon: Shield, color: "text-primary" },
  { name: "Database", label: "Database", Icon: Database, color: "text-info" },
  { name: "Network", label: "Network", Icon: Network, color: "text-neutral" },
  { name: "Target", label: "Target", Icon: Target, color: "text-danger" },
  { name: "Briefcase", label: "Briefcase", Icon: Briefcase, color: "text-primary" },
  { name: "Users", label: "Users", Icon: Users, color: "text-info" },
  { name: "Terminal", label: "Terminal", Icon: Terminal, color: "text-primary" },
  { name: "Cpu", label: "Cpu", Icon: Cpu, color: "text-warning" },
  { name: "Key", label: "Key", Icon: Key, color: "text-warning" },
  { name: "Lock", label: "Lock", Icon: Lock, color: "text-danger" },
] as const;

function renderPositionIcon(iconName?: string, className = "h-5 w-5") {
  const match = AVAILABLE_ICONS.find((item) => item.name === iconName);
  if (match) {
    const IconComponent = match.Icon;
    return <IconComponent className={`${className} ${match.color}`} aria-hidden="true" />;
  }
  return <Briefcase className={`${className} text-primary`} aria-hidden="true" />;
}

export default function PositionsPage() {
  const [currentUserRole, setCurrentUserRole] = useState<string>("Supporter");
  const [positions, setPositions] = useState<JobPosition[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  // Toast notifications
  const [notice, setNotice] = useState<{ kind: OperationToastKind; title: string; description: string } | null>(null);
  const noticeTimer = useRef<number | null>(null);

  const showNotice = useCallback((n: { kind: OperationToastKind; title: string; description: string }) => {
    if (noticeTimer.current !== null) window.clearTimeout(noticeTimer.current);
    setNotice(n);
    noticeTimer.current = window.setTimeout(() => setNotice(null), 5000);
  }, []);

  // Check current session
  useEffect(() => {
    const loadSession = async () => {
      try {
        const response = await fetch("/api/auth/session", { cache: "no-store" });
        if (!response.ok) return;
        const data: unknown = await response.json();
        if (!data || typeof data !== "object") return;
        const session = data as { role?: unknown };
        if (typeof session.role === "string") setCurrentUserRole(session.role);
      } catch {
        // Authenticated server route guards remain authoritative
      }
    };
    void loadSession();
  }, []);

  const isAdmin = currentUserRole === "Admin";

  // Load positions
  useEffect(() => {
    let ignore = false;
    const loadPositions = async () => {
      try {
        const res = await fetch("/api/positions");
        if (!res.ok) throw new Error("Failed to fetch positions");
        const data: unknown = await res.json();
        if (ignore) return;
        if (!Array.isArray(data)) throw new Error("Invalid positions response");
        setPositions(data as JobPosition[]);
        setFetchFailed(false);
      } catch {
        if (!ignore) setFetchFailed(true);
      } finally {
        if (!ignore) setLoading(false);
      }
    };
    void loadPositions();
    return () => {
      ignore = true;
    };
  }, [refreshKey]);

  // Add Position Modal state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isAddModalPresent, setIsAddModalPresent] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  const [addFormData, setAddFormData] = useState({
    title: "",
    status: "ACTIVE" as "ACTIVE" | "STANDBY",
    iconName: "Briefcase",
    description: "",
  });
  const addDialogRef = useRef<HTMLDivElement>(null);
  const addDialogCloseTimer = useRef<number | null>(null);

  useModalFocusTrap(isAddModalOpen, addDialogRef);

  const openAddModal = () => {
    if (addDialogCloseTimer.current !== null) window.clearTimeout(addDialogCloseTimer.current);
    setCreateError("");
    setAddFormData({
      title: "",
      status: "ACTIVE",
      iconName: "Briefcase",
      description: "",
    });
    setIsAddModalPresent(true);
    window.requestAnimationFrame(() => setIsAddModalOpen(true));
  };

  const closeAddModal = useCallback(() => {
    if (isCreating) return;
    setIsAddModalOpen(false);
    if (addDialogCloseTimer.current !== null) window.clearTimeout(addDialogCloseTimer.current);
    addDialogCloseTimer.current = window.setTimeout(() => setIsAddModalPresent(false), 180);
  }, [isCreating]);

  // Edit Position Modal state
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isEditModalPresent, setIsEditModalPresent] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [editError, setEditError] = useState("");
  const [editFormData, setEditFormData] = useState<{
    id: string;
    title: string;
    status: "ACTIVE" | "STANDBY";
    iconName: string;
    description: string;
  }>({
    id: "",
    title: "",
    status: "ACTIVE",
    iconName: "Briefcase",
    description: "",
  });
  const editDialogRef = useRef<HTMLDivElement>(null);
  const editDialogCloseTimer = useRef<number | null>(null);

  useModalFocusTrap(isEditModalOpen, editDialogRef);

  const openEditModal = (pos: JobPosition) => {
    if (editDialogCloseTimer.current !== null) window.clearTimeout(editDialogCloseTimer.current);
    setEditError("");
    setEditFormData({
      id: pos.id,
      title: pos.title,
      status: pos.status,
      iconName: pos.iconName || "Briefcase",
      description: pos.description || "",
    });
    setIsEditModalPresent(true);
    window.requestAnimationFrame(() => setIsEditModalOpen(true));
  };

  const closeEditModal = useCallback(() => {
    if (isEditing) return;
    setIsEditModalOpen(false);
    if (editDialogCloseTimer.current !== null) window.clearTimeout(editDialogCloseTimer.current);
    editDialogCloseTimer.current = window.setTimeout(() => setIsEditModalPresent(false), 180);
  }, [isEditing]);

  // Escape key listener for open modals
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (isAddModalOpen && !isCreating) closeAddModal();
        if (isEditModalOpen && !isEditing) closeEditModal();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isAddModalOpen, isCreating, closeAddModal, isEditModalOpen, isEditing, closeEditModal]);

  // Delete Position state
  const [deleteCandidate, setDeleteCandidate] = useState<JobPosition | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const requestDelete = (pos: JobPosition) => {
    setDeleteError("");
    setDeleteCandidate(pos);
  };

  const confirmDelete = async () => {
    if (!deleteCandidate || isDeleting) return;
    setIsDeleting(true);
    setDeleteError("");

    try {
      const res = await fetch("/api/positions", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: deleteCandidate.id }),
      });
      const data: unknown = await res.json().catch(() => null);
      if (!res.ok) {
        const msg =
          data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string"
            ? (data as { error: string }).error
            : "Failed to delete position.";
        setDeleteError(msg);
        return;
      }

      const removedTitle = deleteCandidate.title;
      setDeleteCandidate(null);
      setPositions((prev) => prev.filter((p) => p.id !== deleteCandidate.id));
      showNotice({
        kind: "success",
        title: "Position removed",
        description: `Position "${removedTitle}" was successfully deleted.`,
      });
      setRefreshKey((k) => k + 1);
    } catch {
      setDeleteError("Network error occurred while deleting position.");
    } finally {
      setIsDeleting(false);
    }
  };

  // Submit handlers
  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isCreating) return;
    setIsCreating(true);
    setCreateError("");

    try {
      const res = await fetch("/api/positions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addFormData),
      });
      const data: unknown = await res.json().catch(() => null);
      if (!res.ok) {
        const msg =
          data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string"
            ? (data as { error: string }).error
            : "Failed to create position.";
        setCreateError(msg);
        return;
      }

      closeAddModal();
      showNotice({
        kind: "success",
        title: "Position created",
        description: `Position "${addFormData.title}" has been successfully created.`,
      });
      setRefreshKey((k) => k + 1);
    } catch {
      setCreateError("Failed to create position. Please try again.");
    } finally {
      setIsCreating(false);
    }
  };

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isEditing) return;
    setIsEditing(true);
    setEditError("");

    try {
      const res = await fetch("/api/positions", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(editFormData),
      });
      const data: unknown = await res.json().catch(() => null);
      if (!res.ok) {
        const msg =
          data && typeof data === "object" && "error" in data && typeof (data as { error: unknown }).error === "string"
            ? (data as { error: string }).error
            : "Failed to update position.";
        setEditError(msg);
        return;
      }

      closeEditModal();
      showNotice({
        kind: "success",
        title: "Position updated",
        description: `Position "${editFormData.title}" has been successfully updated.`,
      });
      setRefreshKey((k) => k + 1);
    } catch {
      setEditError("Failed to update position. Please try again.");
    } finally {
      setIsEditing(false);
    }
  };

  // Stats calculation
  const activePositions = positions.filter((position) => position.status === "ACTIVE").length;
  const totalPositions = positions.length;
  const totalAssignedOperators = positions.reduce((acc, p) => acc + (p.userCount ?? 0), 0);

  return (
    <div className="space-y-7 pb-10">
      {/* Toast Notice */}
      {notice && (
        <OperationToast
          kind={notice.kind}
          title={notice.title}
          description={notice.description}
          onDismiss={() => {
            if (noticeTimer.current !== null) window.clearTimeout(noticeTimer.current);
            setNotice(null);
          }}
        />
      )}

      {/* Header */}
      <header className="flex flex-col justify-between gap-4 border-b border-border pb-6 sm:flex-row sm:items-end">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-primary">
            <Link href="/user-management" className="hover:underline">User Management</Link>
            <span className="text-text-subtle">/</span>
            <span>Positions</span>
          </div>
          <h1 className="mt-3 text-2xl font-semibold leading-8 tracking-tight">Job positions</h1>
          <p className="mt-2 text-sm text-text-muted">Review, configure, and assign role-based access designations for operators.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Link href="/user-management" className="ui-button">
            <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back to users
          </Link>
          <button
            onClick={openAddModal}
            disabled={!isAdmin}
            title={isAdmin ? "Add position" : "Administrator privilege required"}
            className="ui-button ui-button-primary"
          >
            <Plus className="h-4 w-4" aria-hidden="true" /> Add position
          </button>
        </div>
      </header>

      {/* Information Banner */}
      <div className="flex items-start gap-3 rounded-xl border border-border bg-surface-subtle p-4 text-xs leading-relaxed text-text-muted">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
        <div>
          <span className="font-semibold text-text">Operational Access Management:</span>{" "}
          Configure role designations and operational scopes. Deleting a position requires that all assigned operators are first reassigned to maintain identity audit continuity.
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="ui-panel flex items-center gap-4 p-5">
          <div className="rounded-lg border border-primary-border bg-primary-subtle p-3 text-primary">
            <Users className="h-6 w-6" aria-hidden="true" />
          </div>
          <div>
            <div className="text-xs font-medium text-text-muted">Active positions</div>
            <div className="mt-1 text-2xl font-semibold text-text">{activePositions}</div>
          </div>
        </div>
        <div className="ui-panel flex items-center gap-4 p-5">
          <div className="rounded-lg border border-warning-border bg-warning-subtle p-3 text-warning">
            <Briefcase className="h-6 w-6" aria-hidden="true" />
          </div>
          <div>
            <div className="text-xs font-medium text-text-muted">Total positions</div>
            <div className="mt-1 text-2xl font-semibold text-text">{totalPositions}</div>
          </div>
        </div>
        <div className="ui-panel flex items-center gap-4 p-5">
          <div className="rounded-lg border border-border bg-surface-subtle p-3 text-text">
            <Shield className="h-6 w-6 text-primary" aria-hidden="true" />
          </div>
          <div>
            <div className="text-xs font-medium text-text-muted">Assigned operators</div>
            <div className="mt-1 text-2xl font-semibold text-text">{totalAssignedOperators}</div>
          </div>
        </div>
      </div>

      {/* Table Section */}
      <div className="ui-panel overflow-hidden">
        <div className="flex items-center justify-between border-b border-border bg-surface px-5 py-4 sm:px-6">
          <div>
            <h2 className="text-base font-semibold">Operational roles</h2>
            <p className="mt-1 text-sm text-text-muted">Current position definitions, assigned personnel, and availability.</p>
          </div>
        </div>

        <div className="ui-scroll-region">
          <table className="ui-table min-w-[760px]">
            <thead>
              <tr>
                <th scope="col">POSITION ID</th>
                <th scope="col">POSITION TITLE & SCOPE</th>
                <th scope="col">ASSIGNED OPERATORS</th>
                <th scope="col">STATUS</th>
                <th scope="col" className="text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {loading &&
                Array.from({ length: 4 }, (_, idx) => (
                  <tr key={`pos-loading-${idx}`} aria-hidden="true">
                    {Array.from({ length: 5 }, (_, col) => (
                      <td key={col}>
                        <div className="ui-skeleton h-5 w-full" />
                      </td>
                    ))}
                  </tr>
                ))}
              {!loading && fetchFailed && (
                <tr>
                  <td colSpan={5} className="p-6">
                    <RegionState
                      kind="error"
                      title="Position roster unavailable"
                      description="The operational position definitions could not be loaded."
                    />
                  </td>
                </tr>
              )}
              {!loading && !fetchFailed && positions.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-6">
                    <RegionState
                      kind="empty"
                      title="No positions registered"
                      description="No job positions exist in this workspace. Click 'Add position' to register one."
                    />
                  </td>
                </tr>
              )}
              {!loading &&
                !fetchFailed &&
                positions.map((pos) => (
                  <tr key={pos.id}>
                    <td className="font-mono text-sm text-text">{pos.id}</td>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-border bg-surface-subtle">
                          {renderPositionIcon(pos.iconName)}
                        </div>
                        <div>
                          <div className="font-semibold text-text">{pos.title}</div>
                          {pos.description && (
                            <p className="max-w-md line-clamp-1 text-xs text-text-muted">{pos.description}</p>
                          )}
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className="font-mono text-sm text-text">
                        {pos.userCount ?? 0} {pos.userCount === 1 ? "operator" : "operators"}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`ui-badge ${
                          pos.status === "ACTIVE"
                            ? "border-success-border bg-success-subtle text-success"
                            : "border-neutral-border bg-neutral-subtle text-neutral"
                        }`}
                      >
                        <span
                          className={`h-2 w-2 rounded-full ${pos.status === "ACTIVE" ? "bg-success" : "bg-neutral"}`}
                          aria-hidden="true"
                        />
                        {pos.status}
                      </span>
                    </td>
                    <td className="text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => openEditModal(pos)}
                          disabled={!isAdmin}
                          title={isAdmin ? `Edit ${pos.title}` : "Administrator privilege required"}
                          aria-label={`Edit ${pos.title}`}
                          className="ui-button min-h-9 px-2.5"
                        >
                          <Edit2 className="h-4 w-4" aria-hidden="true" />
                        </button>
                        <button
                          onClick={() => requestDelete(pos)}
                          disabled={!isAdmin}
                          title={isAdmin ? `Delete ${pos.title}` : "Administrator privilege required"}
                          aria-label={`Delete ${pos.title}`}
                          className="ui-button min-h-9 px-2.5 text-danger hover:border-danger-border hover:bg-danger-subtle"
                        >
                          <Trash2 className="h-4 w-4" aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Position Modal */}
      {isAddModalPresent && (
        <div
          data-open={isAddModalOpen}
          onClick={(e) => {
            if (e.target === e.currentTarget && !isCreating) closeAddModal();
          }}
          className="pti-modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4"
          role="presentation"
        >
          <div
            ref={addDialogRef}
            data-open={isAddModalOpen}
            className="pti-modal-panel max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-border bg-surface p-6 shadow-[var(--shadow-raised)]"
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-position-title"
            tabIndex={-1}
          >
            <div className="mb-6 flex items-center justify-between">
              <h3 id="add-position-title" className="flex items-center gap-2 text-lg font-semibold">
                <Plus className="h-5 w-5 text-primary" /> Add New Position
              </h3>
              <button
                onClick={closeAddModal}
                className="ui-button min-h-9 px-2"
                aria-label="Close add position dialog"
                disabled={isCreating}
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-4" aria-busy={isCreating}>
              <div>
                <label htmlFor="create-position-title" className="text-xs font-medium text-text-muted">
                  Position Title
                </label>
                <input
                  id="create-position-title"
                  type="text"
                  value={addFormData.title}
                  onChange={(e) => setAddFormData({ ...addFormData, title: e.target.value })}
                  required
                  minLength={2}
                  placeholder="e.g. Threat Intelligence Lead"
                  className="ui-field mt-1"
                  disabled={isCreating}
                  data-autofocus
                />
              </div>

              <div>
                <label htmlFor="create-position-status" className="text-xs font-medium text-text-muted">
                  Status
                </label>
                <SelectMenu
                  id="create-position-status"
                  value={addFormData.status}
                  onValueChange={(val) =>
                    setAddFormData({ ...addFormData, status: val as "ACTIVE" | "STANDBY" })
                  }
                  options={["ACTIVE", "STANDBY"]}
                  className="mt-1"
                  disabled={isCreating}
                />
              </div>

              <div>
                <label className="text-xs font-medium text-text-muted">Designation Icon</label>
                <div className="mt-2 grid grid-cols-5 gap-2">
                  {AVAILABLE_ICONS.map((item) => {
                    const isSelected = addFormData.iconName === item.name;
                    const IconComp = item.Icon;
                    return (
                      <button
                        key={item.name}
                        type="button"
                        onClick={() => setAddFormData({ ...addFormData, iconName: item.name })}
                        title={item.label}
                        aria-label={item.label}
                        className={`flex h-10 w-full items-center justify-center rounded-lg border transition-colors ${
                          isSelected
                            ? "border-primary bg-primary-subtle text-primary ring-2 ring-primary/40"
                            : "border-border bg-surface-subtle text-text-muted hover:border-border-strong hover:bg-surface-raised"
                        }`}
                      >
                        <IconComp className="h-5 w-5" aria-hidden="true" />
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <label htmlFor="create-position-desc" className="text-xs font-medium text-text-muted">
                  Operational Scope (Optional)
                </label>
                <textarea
                  id="create-position-desc"
                  value={addFormData.description}
                  onChange={(e) => setAddFormData({ ...addFormData, description: e.target.value })}
                  rows={2}
                  placeholder="Describe operational responsibilities and clearance duties…"
                  className="ui-field mt-1"
                  disabled={isCreating}
                />
              </div>

              {createError && (
                <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">
                  {createError}
                </p>
              )}

              <div className="flex flex-col-reverse gap-3 border-t border-border pt-5 sm:flex-row sm:justify-end">
                <button type="button" className="ui-button" onClick={closeAddModal} disabled={isCreating}>
                  Cancel
                </button>
                <button type="submit" className="ui-button ui-button-primary" disabled={isCreating}>
                  <Plus className="h-4 w-4" aria-hidden="true" />
                  {isCreating ? "Creating position…" : "Create position"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Position Modal */}
      {isEditModalPresent && (
        <div
          data-open={isEditModalOpen}
          onClick={(e) => {
            if (e.target === e.currentTarget && !isEditing) closeEditModal();
          }}
          className="pti-modal-overlay fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4"
          role="presentation"
        >
          <div
            ref={editDialogRef}
            data-open={isEditModalOpen}
            className="pti-modal-panel max-h-[90vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-border bg-surface p-6 shadow-[var(--shadow-raised)]"
            role="dialog"
            aria-modal="true"
            aria-labelledby="edit-position-title"
            tabIndex={-1}
          >
            <div className="mb-6 flex items-center justify-between">
              <h3 id="edit-position-title" className="flex items-center gap-2 text-lg font-semibold">
                <Edit2 className="h-5 w-5 text-primary" /> Edit position [{editFormData.id}]
              </h3>
              <button
                onClick={closeEditModal}
                className="ui-button min-h-9 px-2"
                aria-label="Close edit position dialog"
                disabled={isEditing}
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <form onSubmit={handleEditSubmit} className="space-y-4" aria-busy={isEditing}>
              <div>
                <label htmlFor="edit-position-title" className="text-xs font-medium text-text-muted">
                  Position Title
                </label>
                <input
                  id="edit-position-title"
                  type="text"
                  value={editFormData.title}
                  onChange={(e) => setEditFormData({ ...editFormData, title: e.target.value })}
                  required
                  minLength={2}
                  className="ui-field mt-1"
                  disabled={isEditing}
                  data-autofocus
                />
              </div>

              <div>
                <label htmlFor="edit-position-status" className="text-xs font-medium text-text-muted">
                  Status
                </label>
                <SelectMenu
                  id="edit-position-status"
                  value={editFormData.status}
                  onValueChange={(val) =>
                    setEditFormData({ ...editFormData, status: val as "ACTIVE" | "STANDBY" })
                  }
                  options={["ACTIVE", "STANDBY"]}
                  className="mt-1"
                  disabled={isEditing}
                />
              </div>

              <div>
                <label className="text-xs font-medium text-text-muted">Designation Icon</label>
                <div className="mt-2 grid grid-cols-5 gap-2">
                  {AVAILABLE_ICONS.map((item) => {
                    const isSelected = editFormData.iconName === item.name;
                    const IconComp = item.Icon;
                    return (
                      <button
                        key={item.name}
                        type="button"
                        onClick={() => setEditFormData({ ...editFormData, iconName: item.name })}
                        title={item.label}
                        aria-label={item.label}
                        className={`flex h-10 w-full items-center justify-center rounded-lg border transition-colors ${
                          isSelected
                            ? "border-primary bg-primary-subtle text-primary ring-2 ring-primary/40"
                            : "border-border bg-surface-subtle text-text-muted hover:border-border-strong hover:bg-surface-raised"
                        }`}
                      >
                        <IconComp className="h-5 w-5" aria-hidden="true" />
                      </button>
                    );
                  })}
                </div>
              </div>

              <div>
                <label htmlFor="edit-position-desc" className="text-xs font-medium text-text-muted">
                  Operational Scope (Optional)
                </label>
                <textarea
                  id="edit-position-desc"
                  value={editFormData.description}
                  onChange={(e) => setEditFormData({ ...editFormData, description: e.target.value })}
                  rows={2}
                  className="ui-field mt-1"
                  disabled={isEditing}
                />
              </div>

              {editError && (
                <p role="alert" className="rounded-lg border border-danger-border bg-danger-subtle p-3 text-sm text-danger">
                  {editError}
                </p>
              )}

              <div className="flex flex-col-reverse gap-3 border-t border-border pt-5 sm:flex-row sm:justify-end">
                <button type="button" className="ui-button" onClick={closeEditModal} disabled={isEditing}>
                  Cancel
                </button>
                <button type="submit" className="ui-button ui-button-primary" disabled={isEditing}>
                  <Edit2 className="h-4 w-4" aria-hidden="true" />
                  {isEditing ? "Saving changes…" : "Save changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Radix Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteCandidate !== null}
        onOpenChange={(open) => {
          if (!open && !isDeleting) {
            setDeleteCandidate(null);
            setDeleteError("");
          }
        }}
        onConfirm={confirmDelete}
        title={deleteCandidate ? `Delete position [${deleteCandidate.id}]` : "Delete position"}
        description={
          deleteCandidate
            ? `Are you sure you want to delete "${deleteCandidate.title}"? This action cannot be undone.${
                (deleteCandidate.userCount ?? 0) > 0
                  ? ` Note: There are currently ${deleteCandidate.userCount} operator(s) assigned to this position.`
                  : ""
              }`
            : ""
        }
        confirmLabel="Delete position"
        confirmVariant="danger"
        isProcessing={isDeleting}
        processingLabel="Deleting position…"
        errorMessage={deleteError}
      />
    </div>
  );
}

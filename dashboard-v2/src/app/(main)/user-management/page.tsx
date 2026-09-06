"use client";
import { useState, useEffect, useSyncExternalStore } from "react";
import Link from "next/link";
import { Briefcase, UserPlus, Edit2, ShieldX, X, Lock } from "lucide-react";
import { isDashboardUser } from "@/lib/dashboardTypes";
import type { DashboardUser } from "@/lib/dashboardTypes";
import { RegionState } from "@/components/ui/RegionState";

const subscribeToSession = (onChange: () => void) => {
  const onStorage = (event: StorageEvent) => {
    if (event.key === "operatorId" || event.key === "userRole" || event.key === null) onChange();
  };
  window.addEventListener("storage", onStorage);
  return () => window.removeEventListener("storage", onStorage);
};

const getCurrentUserId = () => localStorage.getItem("operatorId") || "";
const getCurrentUserRole = () => localStorage.getItem("userRole") || "";
const getEmptySessionValue = () => "";

export default function UserManagementPage() {
  const [users, setUsers] = useState<DashboardUser[]>([]);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);

  // Keep the first server and client render identical. Browser session values are
  // read after hydration, so this route cannot rebuild the theme bootstrapped in <head>.
  const currentUserId = useSyncExternalStore(subscribeToSession, getCurrentUserId, getEmptySessionValue);
  const currentUserRole = useSyncExternalStore(subscribeToSession, getCurrentUserRole, getEmptySessionValue);

  const [formData, setFormData] = useState({ fullName: "", email: "", position: "Lead Sentinel", role: "Supporter" });

  // State สำหรับแก้ไขข้อมูล
  const [editFormData, setEditFormData] = useState({ operatorId: "", fullName: "", email: "", position: "", role: "", newPassword: "" });

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
    const res = await fetch("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(formData)
    });
    if (res.ok) {
      setIsAddModalOpen(false);
      setFormData({ fullName: "", email: "", position: "Lead Sentinel", role: "Supporter" });
      setRefreshKey(prev => prev + 1);
      alert("New Operator Added. Default Password is: default123");
    }
  };

  // ฟังก์ชันเปิดหน้าแก้ไข
  const openEditModal = (user: DashboardUser) => {
    setEditFormData({ ...user, newPassword: "" });
    setIsEditModalOpen(true);
  };

  // ฟังก์ชันบันทึกการแก้ไข
  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // 1. อัปเดตข้อมูลทั่วไป
    const res = await fetch("/api/users", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(editFormData)
    });

    if (res.ok) {
      // 2. ถ้ามีการกรอกรหัสผ่านใหม่ (และเป็นเจ้าของบัญชีตัวเอง) ให้เรียก API เปลี่ยนรหัสผ่านด้วย
      if (editFormData.newPassword && editFormData.operatorId === currentUserId) {
        await fetch("/api/auth/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ operatorId: editFormData.operatorId, newPassword: editFormData.newPassword }),
        });
        alert("Profile and password updated successfully.");
      } else {
        alert("Profile updated successfully.");
      }

      setIsEditModalOpen(false);
      setRefreshKey(prev => prev + 1);
    }
  };

  // ฟังก์ชันลบผู้ใช้
  const handleDelete = async (operatorId: string) => {
    if (operatorId === currentUserId) {
      alert("You cannot delete your own account.");
      return;
    }

    if (confirm("Are you sure you want to terminate this operator's access?")) {
      const res = await fetch("/api/users", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operatorId })
      });
      if (res.ok) setRefreshKey(prev => prev + 1);
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
              <button onClick={() => setIsAddModalOpen(true)} className="ui-button ui-button-primary">
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
                       <button onClick={() => handleDelete(user.operatorId)} className="ui-button min-h-9 px-2 text-danger" aria-label={`Delete ${user.operatorId}`}><ShieldX className="h-4 w-4" aria-hidden="true" /></button>
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

      {/* Modal Add User (อันเดิม) */}
      {isAddModalOpen && (
         <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4">
          <div className="w-full max-w-md rounded-2xl border border-border bg-surface p-6 shadow-[var(--shadow-raised)]">
             <div className="flex justify-between items-center mb-6">
               <h3 className="text-lg font-semibold">Add new operator</h3><button onClick={() => setIsAddModalOpen(false)} className="ui-button min-h-9 px-2" aria-label="Close add operator dialog"><X className="w-5 h-5"/></button>
             </div>
             <form onSubmit={handleAddUser} className="space-y-4">
               <div>
                 <label className="text-xs font-medium text-text-muted">Full name</label><input type="text" value={formData.fullName} onChange={(e) => setFormData({...formData, fullName: e.target.value})} required className="ui-field mt-1" />
               </div>
               <div>
                 <label className="text-xs font-medium text-text-muted">Email</label><input type="email" value={formData.email} onChange={(e) => setFormData({...formData, email: e.target.value})} required className="ui-field mt-1" />
               </div>
               <div>
                 <label className="text-xs font-medium text-text-muted">Position</label><select value={formData.position} onChange={(e) => setFormData({...formData, position: e.target.value})} className="ui-field mt-1">
                   <option value="Lead Sentinel">Lead Sentinel</option>
                   <option value="Data Guardian">Data Guardian</option>
                   <option value="Network Shield">Network Shield</option>
                   <option value="Threat Hunter">Threat Hunter</option>
                 </select>
               </div>
               <div>
                 <label className="text-xs font-medium text-text-muted">Role</label><select value={formData.role} onChange={(e) => setFormData({...formData, role: e.target.value})} className="ui-field mt-1">
                   <option value="Admin">Admin</option>
                   <option value="Supporter">Supporter</option>
                 </select>
               </div>
               <button type="submit" className="ui-button ui-button-primary mt-4 w-full">
                 CREATE OPERATOR
               </button>
             </form>
           </div>
         </div>
      )}

      {/* Modal Edit User */}
      {isEditModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--scrim)] p-4">
          <div className="max-h-[90vh] w-full max-w-md overflow-y-auto rounded-2xl border border-border bg-surface p-6 shadow-[var(--shadow-raised)]">
            <div className="flex justify-between items-center mb-6">
              <h3 className="flex items-center gap-2 text-lg font-semibold"><Edit2 className="w-5 h-5 text-primary"/> Edit operator [{editFormData.operatorId}]
              </h3>
              <button onClick={() => setIsEditModalOpen(false)} className="ui-button min-h-9 px-2" aria-label="Close edit operator dialog"><X className="w-5 h-5"/></button>
            </div>

            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="text-xs font-medium text-text-muted">Full name</label><input type="text" value={editFormData.fullName} onChange={(e) => setEditFormData({...editFormData, fullName: e.target.value})} required className="ui-field mt-1" />
              </div>
              <div>
                <label className="text-xs font-medium text-text-muted">Email</label><input type="email" value={editFormData.email} onChange={(e) => setEditFormData({...editFormData, email: e.target.value})} required className="ui-field mt-1" />
              </div>

              {/* ให้ Admin เท่านั้นที่เปลี่ยนตำแหน่งและ Role ได้ */}
              <div>
                <label className="text-xs font-medium text-text-muted">Position</label><select disabled={currentUserRole !== "Admin"} value={editFormData.position} onChange={(e) => setEditFormData({...editFormData, position: e.target.value})} className="ui-field mt-1">
                  <option value="Lead Sentinel">Lead Sentinel</option>
                  <option value="Data Guardian">Data Guardian</option>
                  <option value="Network Shield">Network Shield</option>
                  <option value="Threat Hunter">Threat Hunter</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-medium text-text-muted">Role</label><select disabled={currentUserRole !== "Admin"} value={editFormData.role} onChange={(e) => setEditFormData({...editFormData, role: e.target.value})} className="ui-field mt-1">
                  <option value="Admin">Admin</option>
                  <option value="Supporter">Supporter</option>
                </select>
              </div>

              {/* ส่วนเปลี่ยนรหัสผ่าน (แสดงเฉพาะตอนแก้ไขบัญชีตัวเอง) */}
              {editFormData.operatorId === currentUserId && (
                <div className="mt-4 border-t border-border pt-4"><label className="mb-2 flex items-center gap-1 text-xs font-medium text-warning">
                    <Lock className="w-3 h-3"/> CHANGE PASSWORD (OPTIONAL)
                  </label>
                  <input type="password" placeholder="Leave blank to keep current password" value={editFormData.newPassword} onChange={(e) => setEditFormData({...editFormData, newPassword: e.target.value})} className="ui-field" />
                </div>
              )}

              <button type="submit" className="ui-button ui-button-primary mt-4 w-full">
                SAVE CHANGES
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

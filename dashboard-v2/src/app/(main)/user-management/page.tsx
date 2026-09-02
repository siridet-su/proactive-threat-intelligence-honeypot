"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { Users, Briefcase, UserPlus, Edit2, ShieldX, X, Lock } from "lucide-react";

export default function UserManagementPage() {
  const [users, setUsers] = useState<any[]>([]);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  
  // เก็บข้อมูลผู้ใช้ที่กำลังล็อกอิน
  const [currentUserId, setCurrentUserId] = useState("");
  const [currentUserRole, setCurrentUserRole] = useState("");

  const [formData, setFormData] = useState({ fullName: "", email: "", position: "Lead Sentinel", role: "Supporter" });
  
  // State สำหรับแก้ไขข้อมูล
  const [editFormData, setEditFormData] = useState({ operatorId: "", fullName: "", email: "", position: "", role: "", newPassword: "" });

  useEffect(() => {
    // ดึงข้อมูลว่าใครกำลังล็อกอินอยู่
    setCurrentUserId(localStorage.getItem("operatorId") || "");
    setCurrentUserRole(localStorage.getItem("userRole") || "");

    const loadUsers = async () => {
      const res = await fetch("/api/users");
      const data = await res.json();
      if(Array.isArray(data)) setUsers(data);
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
  const openEditModal = (user: any) => {
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
    <div className="space-y-6 animate-in fade-in duration-500 pb-10">
      {/* Header (แสดงปุ่ม Add เฉพาะ Admin) */}
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">User Management</h1>
          <p className="text-slate-400 text-sm">Manage operator access permissions and security clearances.</p>
        </div>
        <div className="flex gap-4">
          {currentUserRole === "Admin" && (
            <>
              <Link href="/user-management/positions" className="flex items-center gap-2 px-6 py-3 border border-slate-700 hover:border-purple-500 text-slate-300 rounded-lg transition-colors bg-[#111116] shadow-md">
                <Briefcase className="w-4 h-4" /> Manage Positions
              </Link>
              <button onClick={() => setIsAddModalOpen(true)} className="flex items-center gap-2 px-6 py-3 bg-[#e9d5ff] hover:bg-[#d8b4fe] text-purple-950 font-semibold rounded-lg transition-colors shadow-[0_0_15px_rgba(216,180,254,0.3)]">
                <UserPlus className="w-4 h-4" /> Add New Operator
              </button>
            </>
          )}
        </div>
      </div>

      {/* Table Section */}
      <div className="bg-[#111116] border border-slate-800/80 rounded-xl overflow-hidden mt-8 shadow-xl">
        <div className="p-5 border-b border-slate-800/80 flex justify-between items-center bg-[#15151c]">
          <h2 className="text-lg font-semibold text-slate-200">Active Operator Roster</h2>
        </div>
        
        <table className="w-full text-left text-sm">
          <thead className="text-[10px] uppercase text-slate-500 font-mono border-b border-slate-800/50 bg-[#0a0a0c]">
            <tr>
              <th className="px-6 py-4">OPERATOR ID</th>
              <th className="px-6 py-4">FULL NAME</th>
              <th className="px-6 py-4">POSITION</th>
              <th className="px-6 py-4">ROLE</th>
              <th className="px-6 py-4">STATUS</th>
              <th className="px-6 py-4 text-right">ACTIONS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {users.map((user, i) => {
              // เช็คสิทธิ์: เป็น Admin หรือเป็นตัวเอง
              const canEdit = currentUserRole === "Admin" || user.operatorId === currentUserId;
              const canDelete = currentUserRole === "Admin" && user.operatorId !== currentUserId;

              return (
                <tr key={i} className="hover:bg-slate-800/20 text-slate-300 transition-colors">
                  <td className="px-6 py-4 font-mono text-purple-400 font-medium">
                    {user.operatorId} {user.operatorId === currentUserId && <span className="text-[9px] text-slate-500 ml-1">(YOU)</span>}
                  </td>
                  <td className="px-6 py-4">{user.fullName}</td>
                  <td className="px-6 py-4 text-slate-400">{user.position}</td>
                  <td className="px-6 py-4 text-slate-400">{user.role}</td>
                  <td className="px-6 py-4">
                    <span className="flex items-center gap-2 text-xs">
                      <span className={`w-2 h-2 rounded-full ${user.status === 'Active' ? 'bg-emerald-500' : 'bg-red-500'}`}></span>
                      {user.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right flex justify-end gap-4">
                    {canEdit && (
                       <button onClick={() => openEditModal(user)} className="text-slate-500 hover:text-white transition"><Edit2 className="w-4 h-4" /></button>
                    )}
                    {canDelete && (
                       <button onClick={() => handleDelete(user.operatorId)} className="text-slate-500 hover:text-red-400 transition"><ShieldX className="w-4 h-4" /></button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Modal Add User (อันเดิม) */}
      {isAddModalOpen && (
         <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#111116] border border-slate-800 p-6 rounded-xl w-full max-w-md shadow-2xl">
             <div className="flex justify-between items-center mb-6">
               <h3 className="text-lg font-bold text-white">Add New Operator</h3>
               <button onClick={() => setIsAddModalOpen(false)} className="text-slate-500 hover:text-white"><X className="w-5 h-5"/></button>
             </div>
             <form onSubmit={handleAddUser} className="space-y-4">
               <div>
                 <label className="text-xs text-slate-400 font-mono">FULL NAME</label>
                 <input type="text" value={formData.fullName} onChange={(e) => setFormData({...formData, fullName: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
               </div>
               <div>
                 <label className="text-xs text-slate-400 font-mono">EMAIL</label>
                 <input type="email" value={formData.email} onChange={(e) => setFormData({...formData, email: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
               </div>
               <div>
                 <label className="text-xs text-slate-400 font-mono">POSITION</label>
                 <select value={formData.position} onChange={(e) => setFormData({...formData, position: e.target.value})} className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none">
                   <option value="Lead Sentinel">Lead Sentinel</option>
                   <option value="Data Guardian">Data Guardian</option>
                   <option value="Network Shield">Network Shield</option>
                   <option value="Threat Hunter">Threat Hunter</option>
                 </select>
               </div>
               <div>
                 <label className="text-xs text-slate-400 font-mono">ROLE</label>
                 <select value={formData.role} onChange={(e) => setFormData({...formData, role: e.target.value})} className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none">
                   <option value="Admin">Admin</option>
                   <option value="Supporter">Supporter</option>
                 </select>
               </div>
               <button type="submit" className="w-full bg-purple-700 hover:bg-purple-600 text-white py-3 rounded-lg font-bold tracking-wider mt-4">
                 CREATE OPERATOR
               </button>
             </form>
           </div>
         </div>
      )}

      {/* Modal Edit User */}
      {isEditModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#111116] border border-slate-800 p-6 rounded-xl w-full max-w-md shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Edit2 className="w-5 h-5 text-purple-400"/> Edit Operator [{editFormData.operatorId}]
              </h3>
              <button onClick={() => setIsEditModalOpen(false)} className="text-slate-500 hover:text-white"><X className="w-5 h-5"/></button>
            </div>
            
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="text-xs text-slate-400 font-mono">FULL NAME</label>
                <input type="text" value={editFormData.fullName} onChange={(e) => setEditFormData({...editFormData, fullName: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
              </div>
              <div>
                <label className="text-xs text-slate-400 font-mono">EMAIL</label>
                <input type="email" value={editFormData.email} onChange={(e) => setEditFormData({...editFormData, email: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
              </div>
              
              {/* ให้ Admin เท่านั้นที่เปลี่ยนตำแหน่งและ Role ได้ */}
              <div>
                <label className="text-xs text-slate-400 font-mono">POSITION</label>
                <select disabled={currentUserRole !== "Admin"} value={editFormData.position} onChange={(e) => setEditFormData({...editFormData, position: e.target.value})} className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none disabled:opacity-50">
                  <option value="Lead Sentinel">Lead Sentinel</option>
                  <option value="Data Guardian">Data Guardian</option>
                  <option value="Network Shield">Network Shield</option>
                  <option value="Threat Hunter">Threat Hunter</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-400 font-mono">ROLE</label>
                <select disabled={currentUserRole !== "Admin"} value={editFormData.role} onChange={(e) => setEditFormData({...editFormData, role: e.target.value})} className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none disabled:opacity-50">
                  <option value="Admin">Admin</option>
                  <option value="Supporter">Supporter</option>
                </select>
              </div>

              {/* ส่วนเปลี่ยนรหัสผ่าน (แสดงเฉพาะตอนแก้ไขบัญชีตัวเอง) */}
              {editFormData.operatorId === currentUserId && (
                <div className="pt-4 mt-4 border-t border-slate-800">
                  <label className="text-xs text-amber-500 font-mono flex items-center gap-1 mb-2">
                    <Lock className="w-3 h-3"/> CHANGE PASSWORD (OPTIONAL)
                  </label>
                  <input type="password" placeholder="Leave blank to keep current password" value={editFormData.newPassword} onChange={(e) => setEditFormData({...editFormData, newPassword: e.target.value})} className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 focus:border-amber-500 outline-none" />
                </div>
              )}

              <button type="submit" className="w-full bg-purple-700 hover:bg-purple-600 text-white py-3 rounded-lg font-bold tracking-wider mt-4 transition-colors">
                SAVE CHANGES
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
"use client";
import { useState, useEffect } from "react";
import { Settings, User, ShieldCheck, Key, Edit2, X, Info } from "lucide-react";

export default function ProfilePage() {
  const [user, setUser] = useState<any>(null);
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
    if (!operatorId) return;

    try {
      const res = await fetch(`/api/users/${operatorId}`);
      if (res.ok) {
        const data = await res.json();
        setUser(data);
        setInfoForm({ fullName: data.fullName, email: data.email });
      }
    } catch (err) {
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

  if (loading) return <div className="text-slate-500 animate-pulse font-mono">LOADING PROFILE DATA...</div>;
  if (!user) return <div className="text-red-500 font-mono">ERROR: PROFILE NOT FOUND</div>;

  return (
    <div className="animate-in fade-in duration-500 max-w-6xl">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8 border-b border-slate-800/50 pb-6">
        <Settings className="w-8 h-8 text-slate-400" />
        <h1 className="text-3xl font-bold text-white">User Profile</h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column (Metadata) */}
        <div className="lg:col-span-1 space-y-8">
          <div className="bg-[#111116] border border-slate-800/50 rounded-xl p-6 shadow-lg">
            <h2 className="text-2xl font-bold text-white mb-1">{user.fullName}</h2>
            <p className="text-purple-400 text-sm font-mono mb-6">{user.position}</p>
            
            <div className="bg-[#0a0a0c] border border-slate-800 p-3 rounded flex items-center gap-2 text-xs font-mono text-slate-300 mb-8">
              <User className="w-4 h-4 text-slate-500" />
              OP-ID: {user.operatorId}
            </div>

            <div className="flex items-center gap-2 text-white font-semibold mb-4 border-b border-slate-800 pb-2">
              <Info className="w-4 h-4" /> Account Metadata
            </div>
            
            <div className="space-y-4 text-sm">
              <div>
                <p className="text-slate-500 mb-1 text-xs">Account Created</p>
                <p className="text-slate-300">{user.createdAt ? new Date(user.createdAt).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) + ' UTC' : 'N/A'}</p>
              </div>
              <div>
                <p className="text-slate-500 mb-1 text-xs">Clearance Level</p>
                <p className="text-slate-300 flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${user.role === 'Admin' ? 'bg-purple-500' : 'bg-emerald-500'}`}></span>
                  {user.role === 'Admin' ? 'Tier 4 (Admin)' : 'Tier 2 (Supporter)'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (Editable Info) */}
        <div className="lg:col-span-2 space-y-8">
          
          {/* Personal Information */}
          <div className="bg-[#0a0a0c] border border-slate-800/50 rounded-xl p-6">
            <div className="flex justify-between items-center mb-6 border-b border-slate-800/50 pb-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <User className="w-5 h-5 text-slate-400" /> Personal Information
              </h3>
              <button onClick={() => setIsEditInfoOpen(true)} className="flex items-center gap-2 text-xs text-slate-400 hover:text-white transition-colors">
                <Edit2 className="w-3 h-3" /> Edit Information
              </button>
            </div>
            
            <div className="grid grid-cols-2 gap-8 text-sm">
              <div>
                <p className="text-slate-500 text-xs mb-1 font-mono">Full Name</p>
                <p className="text-slate-200">{user.fullName}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1 font-mono">Email Address</p>
                <p className="text-slate-200">{user.email}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1 font-mono">Position</p>
                <p className="text-slate-200">{user.position}</p>
              </div>
            </div>
          </div>

          {/* Security Controls */}
          <div className="bg-[#0a0a0c] border border-slate-800/50 rounded-xl p-6">
            <div className="mb-6 border-b border-slate-800/50 pb-4">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-purple-400" /> Security Controls
              </h3>
            </div>
            
            <div className="flex justify-between items-center">
              <div>
                <h4 className="text-slate-200 font-mono text-sm mb-1">Authentication Credentials</h4>
                <p className="text-slate-500 text-xs">Update your access password regularly to maintain security.</p>
              </div>
              <button onClick={() => setIsEditPasswordOpen(true)} className="flex items-center gap-2 text-xs text-slate-400 hover:text-white border border-slate-700 px-4 py-2 rounded transition-colors bg-[#111116]">
                <Key className="w-3 h-3" /> Change Password
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* Modal: Edit Personal Info */}
      {isEditInfoOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#111116] border border-slate-800 p-6 rounded-xl w-full max-w-md shadow-2xl">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-bold text-white">Edit Personal Info</h3>
              <button onClick={() => setIsEditInfoOpen(false)} className="text-slate-500 hover:text-white"><X className="w-5 h-5"/></button>
            </div>
            <form onSubmit={handleInfoSubmit} className="space-y-4">
              <div>
                <label className="text-xs text-slate-400 font-mono">FULL NAME</label>
                <input type="text" value={infoForm.fullName} onChange={(e) => setInfoForm({...infoForm, fullName: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
              </div>
              <div>
                <label className="text-xs text-slate-400 font-mono">EMAIL</label>
                <input type="email" value={infoForm.email} onChange={(e) => setInfoForm({...infoForm, email: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
              </div>
              <button type="submit" className="w-full bg-purple-700 hover:bg-purple-600 text-white py-3 rounded-lg font-bold tracking-wider mt-4">
                SAVE CHANGES
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Change Password */}
      {isEditPasswordOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#111116] border border-slate-800 p-6 rounded-xl w-full max-w-md shadow-2xl">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-lg font-bold text-white">Change Password</h3>
              <button onClick={() => setIsEditPasswordOpen(false)} className="text-slate-500 hover:text-white"><X className="w-5 h-5"/></button>
            </div>
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <div>
                <label className="text-xs text-slate-400 font-mono">NEW PASSWORD</label>
                <input type="password" value={passwordForm.newPassword} onChange={(e) => setPasswordForm({...passwordForm, newPassword: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
              </div>
              <div>
                <label className="text-xs text-slate-400 font-mono">CONFIRM PASSWORD</label>
                <input type="password" value={passwordForm.confirmPassword} onChange={(e) => setPasswordForm({...passwordForm, confirmPassword: e.target.value})} required className="w-full bg-[#0a0a0c] border border-slate-800 text-white rounded p-2 mt-1 focus:border-purple-500 outline-none" />
              </div>
              {passwordError && <p className="text-red-500 text-xs text-center">{passwordError}</p>}
              <button type="submit" className="w-full bg-purple-700 hover:bg-purple-600 text-white py-3 rounded-lg font-bold tracking-wider mt-4">
                UPDATE CREDENTIALS
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
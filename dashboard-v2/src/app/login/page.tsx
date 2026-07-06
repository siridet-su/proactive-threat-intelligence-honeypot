import LoginForm from "@/components/auth/LoginForm";

export default function LoginPage() {
  return (
    <main className="relative min-h-screen bg-[#050507] flex flex-col items-center justify-center overflow-hidden selection:bg-purple-500/30 p-4">
      {/* Background Glow Effect */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-purple-900/10 blur-[150px] rounded-full pointer-events-none"></div>
      
      {/* Header Logo สำหรับหน้า Login */}
      <div className="absolute top-6 left-8 text-xl font-bold tracking-wider text-purple-200 z-10">
        PTI-Honeypot
      </div>

      {/* เรียกใช้งาน Login Form Component */}
      <LoginForm />
    </main>
  );
}
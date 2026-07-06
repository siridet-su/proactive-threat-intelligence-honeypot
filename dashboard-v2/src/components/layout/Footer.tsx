export default function Footer() {
  return (
    <footer className="w-full border-t border-slate-800/50 bg-slate-950/80 py-6 px-8 absolute bottom-0 flex flex-col md:flex-row items-center justify-between text-xs text-slate-500 font-mono">
      <div>
        <p className="font-bold text-slate-300 mb-1">PTI-Honeypot</p>
        <p>© 2024 PTI-Honeypot Cyber Defense. All Rights Reserved.</p>
        <p>Security Clearance Level 4 Required.</p>
      </div>
      <div className="flex gap-6 mt-4 md:mt-0">
        <a href="#" className="hover:text-purple-400 transition">Privacy Policy</a>
        <a href="#" className="hover:text-purple-400 transition">Terms of Engagement</a>
        <a href="#" className="hover:text-purple-400 transition">Support</a>
      </div>
    </footer>
  );
}
import Link from "next/link";

export default function HeroSection() {
  return (
    <section className="flex flex-col items-center text-center max-w-3xl mx-auto z-10">
      {/* Eyebrow */}
      <div className="flex items-center gap-4 mb-4 text-xs font-mono tracking-[0.3em] text-slate-400 uppercase">
        <div className="h-[1px] w-8 bg-slate-600"></div>
        Vigilance Through Deception
        <div className="h-[1px] w-8 bg-slate-600"></div>
      </div>

      {/* Main Title */}
      <h1 className="text-6xl md:text-8xl font-black text-white tracking-tight mb-6">
        PTI-HONEPOT
      </h1>

      {/* Subtitle */}
      <p className="text-slate-400 text-lg md:text-xl leading-relaxed mb-10 max-w-2xl">
        Advanced Cyber Intelligence & Decoy Operations. Neutralize threats by
        becoming the target they can't resist. High-fidelity honeypot systems for the
        modern enterprise.
      </p>

      {/* Action Button */}
      <Link 
        href="/login" 
        className="bg-purple-700 hover:bg-purple-600 text-white px-8 py-4 rounded-md font-mono text-sm tracking-widest flex items-center gap-3 transition-all shadow-[0_0_20px_rgba(126,34,206,0.4)] hover:shadow-[0_0_30px_rgba(126,34,206,0.6)]"
      >
        ACCESS TERMINAL
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
      </Link>
    </section>
  );
}
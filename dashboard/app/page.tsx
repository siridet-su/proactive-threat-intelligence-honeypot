'use client';

import dynamic from 'next/dynamic';

const HoneypotDashboard = dynamic(
  () => import('@/components/dashboard/HoneypotDashboard').then(mod => mod.HoneypotDashboard),
  { ssr: false, loading: () => <div className="min-h-screen bg-[#020617] flex items-center justify-center text-cyan-500">Initializing Security Console...</div> }
);

export default function Home() {
  return <HoneypotDashboard />;
}

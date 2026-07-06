import Navbar from "@/components/layout/Navbar";
import Footer from "@/components/layout/Footer";
import HeroSection from "@/components/home/HeroSection";

export default function Home() {
  return (
    <main className="relative min-h-screen bg-[#0a0a0c] flex flex-col items-center justify-center overflow-hidden selection:bg-purple-500/30">
      {/* Background Gradient Effect */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[400px] bg-purple-900/20 blur-[120px] rounded-full pointer-events-none"></div>

      <Navbar />
      
      <HeroSection />

      <Footer />
    </main>
  );
}
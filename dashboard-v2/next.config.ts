import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Allow LAN access for development to prevent HMR blocking
  allowedDevOrigins: ['192.168.1.8', 'localhost'],
  serverExternalPackages: ["geoip-lite"],
};

export default nextConfig;

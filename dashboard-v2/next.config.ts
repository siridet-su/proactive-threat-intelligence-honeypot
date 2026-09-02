import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The staging pipeline deploys the exact server produced by `next build`.
  // The existing production service may continue to use `next start` until
  // its separately approved release process changes.
  output: "standalone",
  // Allow LAN access for development to prevent HMR blocking
  allowedDevOrigins: ["192.168.1.8", "localhost", "10.58.33.42"],
  serverExternalPackages: ["geoip-lite"],
};

export default nextConfig;

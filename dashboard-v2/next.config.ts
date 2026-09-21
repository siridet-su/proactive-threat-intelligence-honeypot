import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The staging pipeline deploys the exact server produced by `next build`.
  // The existing production service may continue to use `next start` until
  // its separately approved release process changes.
  output: "standalone",
  // The CLI checker spawns a detached child process. Some production build
  // runners suppress that child's stdout, which leaves Next unable to parse
  // `tsc --showConfig` even though TypeScript exits successfully. Use the
  // compiler API so type checking remains enabled without that process-boundary
  // dependency.
  experimental: {
    useTypeScriptCli: false,
  },
  // Allow LAN access for development to prevent HMR blocking
  allowedDevOrigins: ["192.168.1.8", "192.168.89.112", "10.58.33.42", "100.118.43.30", "localhost"],
  serverExternalPackages: ["geoip-lite", "bcryptjs"],
};

export default nextConfig;

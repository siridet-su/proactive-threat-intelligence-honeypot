import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The staging pipeline deploys the exact server produced by `next build`.
  // The existing production service may continue to use `next start` until
  // its separately approved release process changes.
  output: "standalone",
};

export default nextConfig;

import type { Metadata } from "next";
import DeploymentBadge from "@/components/layout/DeploymentBadge";
import "./globals.css";

export const metadata: Metadata = {
  title: "PTI-Honeypot Threat Intelligence",
  description: "Read-only threat intelligence dashboard backed by the canonical monitor API.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">
        <DeploymentBadge />
        {children}
      </body>
    </html>
  );
}

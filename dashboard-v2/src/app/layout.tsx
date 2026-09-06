import type { Metadata } from "next";
import DeploymentBadge from "@/components/layout/DeploymentBadge";
import ThemeProvider from "@/components/theme/ThemeProvider";
import { themeBootstrap } from "@/lib/theme";
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
    <html lang="en" className="h-full antialiased" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body className="min-h-full flex flex-col">
        <ThemeProvider>
          <DeploymentBadge />
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}

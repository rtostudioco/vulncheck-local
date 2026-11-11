import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Sentinel Desk 1.0 — Local Intelligence. Human-Controlled Defense.",
  description:
    "Local-first personal SOC investigation & threat detection workbench. Demo build with clearly-labeled synthetic telemetry — not an antivirus, EDR, or enterprise SIEM.",
  keywords: ["SOC", "threat detection", "incident response", "Windows Event Log", "detection rules", "MITRE ATT&CK"],
  authors: [{ name: "Sentinel Desk Core Team" }],
  icons: {
    icon: "/logo.svg",
  },
  openGraph: {
    title: "Sentinel Desk 1.0",
    description: "Local Intelligence. Human-Controlled Defense.",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#0b0f0e",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
      </body>
    </html>
  );
}

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DHRUVA AI-SOC",
  description:
    "DHRUVA AI-SOC analyst dashboard — glass-box · campaign · copilot.",
  // Brand mark (WO-H52): the Pole-Star icon system. SVG favicon is primary
  // (crisp at every size, orbit auto-dropped at small sizes per the brand
  // spec); .ico + PNGs cover legacy browsers, Apple touch, and PWA install.
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "any" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180" }],
  },
  manifest: "/site.webmanifest",
};

export const viewport = {
  themeColor: "#0d3346",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "DHRUVA AI-SOC",
  description:
    "DHRUVA AI-SOC analyst dashboard — glass-box · campaign · copilot.",
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

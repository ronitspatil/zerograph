import type { Metadata } from "next";
import "./globals.css";
import "./global-map.css";
export const metadata: Metadata = {
  title: "ZeroGraph · Identity & Data Security",
  description: "Identity and data access security console.",
  icons: { icon: "/favicon.svg" },
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

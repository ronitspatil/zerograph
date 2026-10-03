import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "ZeroGraph · Identity & Data Security",
  description: "Understand every identity. Protect every access path.",
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

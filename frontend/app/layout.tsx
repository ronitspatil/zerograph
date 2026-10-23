import type { Metadata, Viewport } from "next";
import { Chakra_Petch, Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import "./dashboard.css";
import "./global-map.css";
import "./optimized.css";
/*
 * Type system (rationale in app/globals.css, "Type system"): self-hosted at build time by
 * next/font (latin subset, only the weights used, font-display swap and a size-adjusted
 * fallback so text never shifts when the face arrives).
 */
const display = Chakra_Petch({
  subsets: ["latin"],
  weight: ["500", "600"],
  display: "swap",
  variable: "--font-display-face",
  adjustFontFallback: true,
});
const text = Inter({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
  variable: "--font-text-face",
});
const mono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  display: "swap",
  variable: "--font-mono-face",
});
/** Bump when the icon artwork changes so browsers drop cached tab icons. */
const ICON_VERSION = "5";
export const metadata: Metadata = {
  title: "ZeroGraph · Identity & Data Security",
  description: "Identity and data access security console.",
  icons: {
    icon: [
      { url: `/favicon.ico?v=${ICON_VERSION}`, sizes: "32x32" },
      { url: `/favicon.svg?v=${ICON_VERSION}`, type: "image/svg+xml" },
    ],
    apple: [
      {
        url: `/apple-touch-icon.png?v=${ICON_VERSION}`,
        sizes: "180x180",
        type: "image/png",
      },
    ],
  },
  manifest: `/manifest.webmanifest?v=${ICON_VERSION}`,
};
export const viewport: Viewport = {
  themeColor: "#0a101b",
  colorScheme: "dark",
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${display.variable} ${text.variable} ${mono.variable}`}
    >
      <body>{children}</body>
    </html>
  );
}

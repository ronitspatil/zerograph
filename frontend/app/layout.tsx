import type { Metadata, Viewport } from "next";
import "./globals.css";
import "./global-map.css";
import "./optimized.css";
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
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

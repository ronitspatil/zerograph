import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { metadata, viewport } from "@/app/layout";
import { config } from "@/middleware";

const pub = (name: string) => readFileSync(resolve("public", name));

describe("Browser icons", () => {
  it("advertises versioned ico, svg and apple-touch icons plus theme colour", () => {
    const icons = metadata.icons as {
      icon: { url: string }[];
      apple: { url: string }[];
    };
    const urls = [...icons.icon, ...icons.apple].map((i) => i.url);
    expect(urls).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^\/favicon\.ico\?v=\w+$/),
        expect.stringMatching(/^\/favicon\.svg\?v=\w+$/),
        expect.stringMatching(/^\/apple-touch-icon\.png\?v=\w+$/),
      ]),
    );
    expect(viewport.themeColor).toBe("#0a101b");
  });

  it("ships a real multi-size .ico and PNG icons", () => {
    const ico = pub("favicon.ico");
    expect(ico.readUInt16LE(2)).toBe(1); // icon resource
    const count = ico.readUInt16LE(4);
    const sizes = Array.from({ length: count }, (_, i) => ico[6 + i * 16]);
    expect(sizes).toEqual([16, 32, 48]);
    for (const [file, size] of [
      ["apple-touch-icon.png", 180],
      ["icon-192.png", 192],
      ["icon-512.png", 512],
    ] as const) {
      const png = pub(file);
      expect(png.subarray(1, 4).toString()).toBe("PNG");
      expect(png.readUInt32BE(16)).toBe(size);
    }
    const manifest = JSON.parse(pub("manifest.webmanifest").toString());
    expect(manifest.theme_color).toBe("#0a101b");
  });

  it("keeps icons out of the middleware while pages still get CSP", () => {
    const matcher = new RegExp(`^${config.matcher[0]}$`);
    for (const path of [
      "/favicon.ico",
      "/favicon.svg",
      "/apple-touch-icon.png",
      "/icon-192.png",
      "/manifest.webmanifest",
    ])
      expect(matcher.test(path), path).toBe(false);
    for (const path of ["/", "/login"])
      expect(matcher.test(path), path).toBe(true);
  });
});

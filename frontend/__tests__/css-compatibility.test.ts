import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import postcss from "postcss";
import tailwind from "@tailwindcss/postcss";
import { describe, expect, it } from "vitest";
import { cn } from "@/lib/utils";

describe("Tailwind 4 theme and utility compatibility", () => {
  it("compiles preserved theme colors and caller utility overrides", async () => {
    const file = resolve("app/globals.css");
    const source = await readFile(file, "utf8");
    const output = await postcss([tailwind({ base: process.cwd() })]).process(
      source +
        '\n@source inline("bg-background text-foreground text-primary border-border bg-primary p-4 text-sm");',
      { from: file },
    );
    for (const [name, value] of Object.entries({
      border: "#243143",
      background: "#0a101b",
      foreground: "#e5edf8",
      primary: "#80e8ce",
    })) {
      expect(output.css).toContain(`--color-${name}: ${value}`);
    }
    for (const selector of [
      ".bg-background",
      ".text-foreground",
      ".text-primary",
      ".border-border",
      ".bg-primary",
      ".p-4",
      ".text-sm",
    ]) {
      let found = false;
      output.root.walkRules(selector, () => {
        found = true;
      });
      expect(found, selector).toBe(true);
    }
    expect(output.css.indexOf(".p-4")).toBeLessThan(
      output.css.indexOf(".button-primary"),
    );
    expect(cn("px-2 py-1 bg-background", "px-4 bg-primary")).toBe(
      "py-1 px-4 bg-primary",
    );
    expect(cn("outline-none", "outline-hidden")).toBe("outline-hidden");
  });
});

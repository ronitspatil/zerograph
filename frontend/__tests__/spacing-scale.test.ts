import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// 1px optical nudges and the 2px inset of the segmented graph-view switch are
// the only deliberate exceptions to the 4px spacing scale.
const allowed = (selector: string, px: number) =>
  px === 0 || px === 1 || (px === 2 && selector.includes(".graph-view-switch"));

describe("Spacing scale", () => {
  it.each(["app/globals.css", "app/global-map.css", "app/optimized.css"])(
    "keeps every margin, padding and gap in %s on 4px steps",
    (file) => {
      const css = readFileSync(resolve(file), "utf8");
      const offenders: string[] = [];
      for (const [, selector, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g))
        for (const [, prop, value] of body.matchAll(
          /((?:margin|padding|gap|row-gap|column-gap)(?:-[a-z]+)?)\s*:([^;]+);/g,
        ))
          for (const [, n] of value.matchAll(/(-?\d+(?:\.\d+)?)px/g)) {
            const px = Math.abs(Number(n));
            if (px % 4 && !allowed(selector, px))
              offenders.push(`${selector.trim()} { ${prop}: ${value.trim()} }`);
          }
      expect(offenders).toEqual([]);
    },
  );

  it("defines spacing tokens and stabilises scrollbars", () => {
    const css = readFileSync(resolve("app/globals.css"), "utf8");
    for (const [token, px] of [
      ["--space-1", 4],
      ["--space-2", 8],
      ["--space-4", 16],
      ["--space-6", 24],
    ])
      expect(css).toContain(`${token}: ${px}px`);
    expect(css).toMatch(/scrollbar-gutter:\s*stable/);
    expect(css).toMatch(/prefers-reduced-motion:\s*reduce/);
  });
});

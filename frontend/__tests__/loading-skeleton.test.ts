import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("Console loading skeleton", () => {
  it("lays its rows out full width, not centred like the old spinner", () => {
    // The base .loading-state rule centres its content; the skeleton's empty grids then
    // shrank to slivers in the middle of the page on every refresh and sign-in.
    const css = readFileSync(resolve("app/dashboard.css"), "utf8");
    const rule = css.match(/\.loading-state \{([^}]*)\}/)?.[1] ?? "";
    expect(rule).toMatch(/align-items:\s*stretch/);
    expect(rule).toMatch(/justify-content:\s*flex-start/);
  });
});

import { describe, expect, it } from "vitest";
import { NextRequest } from "next/server";
import { middleware } from "@/middleware";
describe("worker CSP", () => {
  it("allows only same-origin workers while preserving strict nonce script policy", () => {
    const csp = middleware(
      new NextRequest("https://console.example/"),
    ).headers.get("Content-Security-Policy")!;
    expect(csp.split(";").map((p) => p.trim())).toContain("worker-src 'self'");
    expect(csp).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toContain("worker-src blob:");
  });
});

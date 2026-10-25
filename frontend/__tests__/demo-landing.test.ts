// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { NextRequest } from "next/server";
import { middleware } from "@/middleware";
import { seal, unseal } from "@/lib/session";
import { POST as demoSignIn } from "@/app/api/auth/demo/route";

const base = "https://console.example";
const visit = (path: string, cookie?: string) =>
  middleware(
    new NextRequest(base + path, {
      headers: cookie ? { cookie: `zg_session=${cookie}` } : {},
    }),
  );
const sessionSet = (response: Response) =>
  response.headers.getSetCookie().find((c) => c.startsWith("zg_session="));
const sealedFrom = (setCookie: string) =>
  setCookie.slice("zg_session=".length).split(";")[0];

beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  vi.stubEnv("ZG_ENVIRONMENT", "test");
  vi.stubEnv("ZG_SESSION_SECRET", "s".repeat(64));
  vi.stubEnv("ZG_PUBLIC_URL", base);
  vi.stubEnv("ZG_DEMO_MODE", "true");
  vi.stubEnv("ZG_DEMO_TOKEN", "demo-credential");
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("demo landing", () => {
  it("opens / on the console with a fresh demo session and no sign-in page", async () => {
    const response = await visit("/");
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    const cookie = sessionSet(response)!;
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=lax/i);
    expect(cookie).toMatch(/Secure/i);
    expect(cookie).toMatch(/Max-Age=3600/);
    const payload = await unseal(sealedFrom(cookie));
    expect(payload).toMatchObject({
      access_token: "demo-credential",
      kind: "demo",
    });
    // The page itself renders with that session already in the request.
    expect(response.headers.get("x-middleware-request-cookie")).toContain(
      `zg_session=${sealedFrom(cookie)}`,
    );
    expect(response.headers.get("Content-Security-Policy")).toContain(
      "script-src 'self' 'nonce-",
    );
  });

  it("keeps an existing session, demo or organization, untouched", async () => {
    for (const kind of ["demo", "oidc"]) {
      const sealed = await seal({ access_token: "credential", kind });
      const response = await visit("/", sealed);
      expect(response.status).toBe(200);
      expect(sessionSet(response)).toBeUndefined();
    }
  });

  it("replaces an expired or tampered session with the demo", async () => {
    const expired = await seal({ access_token: "credential" }, -60);
    for (const cookie of [expired, "not-a-session"]) {
      const sealed = sessionSet(await visit("/", cookie))!;
      expect((await unseal(sealedFrom(sealed))).kind).toBe("demo");
    }
  });

  it("gives /login a demo session too, so signing out lands on the demo", async () => {
    // The login page then redirects to the dashboard (see the login page tests).
    const response = await visit("/login");
    expect(response.status).toBe(200);
    expect((await unseal(sealedFrom(sessionSet(response)!))).access_token).toBe(
      "demo-credential",
    );
    const signedIn = await visit(
      "/login",
      await seal({ access_token: "credential", kind: "oidc" }),
    );
    expect(sessionSet(signedIn)).toBeUndefined();
  });

  it("still shows /login for single sign-on errors", async () => {
    const response = await visit("/login?error=authentication");
    expect(response.status).toBe(200);
    expect(response.headers.get("location")).toBeNull();
    expect(sessionSet(response)).toBeUndefined();
  });

  it("only lands on the root page", async () => {
    const response = await visit("/elsewhere");
    expect(sessionSet(response)).toBeUndefined();
  });

  it("stays on the sign-in page instead of looping when sessions can't be sealed", async () => {
    vi.stubEnv("ZG_SESSION_SECRET", "short");
    // No session, so / sends the visitor to /login, which then shows the sign-in page.
    expect(sessionSet(await visit("/login"))).toBeUndefined();
    expect(sessionSet(await visit("/"))).toBeUndefined();
  });
});

describe("outside demo mode", () => {
  it.each([
    ["off", { ZG_DEMO_MODE: "false", ZG_DEMO_TOKEN: "demo-credential" }],
    ["unset", { ZG_DEMO_MODE: "", ZG_DEMO_TOKEN: "demo-credential" }],
    ["without a demo token", { ZG_DEMO_MODE: "true", ZG_DEMO_TOKEN: "" }],
  ])("never creates a session when the demo is %s", async (_, env) => {
    for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
    const root = await visit("/");
    expect(root.status).toBe(200);
    expect(sessionSet(root)).toBeUndefined();
    expect(root.headers.get("x-middleware-request-cookie")).toBeNull();
    // Unauthenticated visitors keep the sign-in page.
    for (const path of ["/login", "/login?error=authentication"]) {
      const login = await visit(path);
      expect(login.status).toBe(200);
      expect(login.headers.get("location")).toBeNull();
      expect(sessionSet(login)).toBeUndefined();
    }
    const explicit = await demoSignIn(
      new Request(base + "/api/auth/demo", {
        method: "POST",
        headers: { origin: base },
      }),
    );
    expect(explicit.status).toBe(403);
    expect(sessionSet(explicit)).toBeUndefined();
  });

  it("demo sign-in still checks the origin first", async () => {
    const response = await demoSignIn(
      new Request(base + "/api/auth/demo", {
        method: "POST",
        headers: { origin: "https://attacker.example" },
      }),
    );
    expect(response.status).toBe(403);
    expect(sessionSet(response)).toBeUndefined();
  });
});

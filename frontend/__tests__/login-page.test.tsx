// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  currentSession: vi.fn(),
  redirect: vi.fn((to: string) => {
    throw new Error(`redirect ${to}`);
  }),
}));
vi.mock("@/lib/session", () => ({ currentSession: mocks.currentSession }));
vi.mock("next/navigation", () => ({ redirect: mocks.redirect }));
import LoginPage from "@/app/login/page";
import RootPage from "@/app/page";

const login = (error?: string) =>
  LoginPage({ searchParams: Promise.resolve(error ? { error } : {}) });
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv("ZG_DEMO_MODE", "true");
  vi.stubEnv("ZG_DEMO_TOKEN", "demo-credential");
  mocks.currentSession.mockResolvedValue({ accessToken: "t", kind: "demo" });
});
afterEach(() => vi.unstubAllEnvs());

describe("login page", () => {
  it("returns a demo deployment to the dashboard", async () => {
    await expect(login()).rejects.toThrow("redirect /");
  });

  it("shows single sign-on errors instead of redirecting", async () => {
    const page = await login("authentication");
    expect(page.props).toMatchObject({ demo: true, error: "authentication" });
    expect(mocks.redirect).not.toHaveBeenCalled();
  });

  it("shows the sign-in page when no demo session could be made", async () => {
    mocks.currentSession.mockResolvedValue(null);
    expect((await login()).props.demo).toBe(true);
  });

  it("is unchanged outside demo mode, even when signed in", async () => {
    vi.stubEnv("ZG_DEMO_MODE", "false");
    const page = await login();
    expect(page.props.demo).toBe(false);
    expect(mocks.redirect).not.toHaveBeenCalled();
  });
});

describe("console page", () => {
  it("still sends visitors without a session to sign-in", async () => {
    vi.stubEnv("ZG_DEMO_MODE", "false");
    mocks.currentSession.mockResolvedValue(null);
    await expect(RootPage()).rejects.toThrow("redirect /login");
  });

  it("labels the demo and an organization session apart and passes SSO state", async () => {
    vi.stubEnv("ZG_OIDC_ISSUER", "https://issuer.example");
    vi.stubEnv("ZG_OIDC_CLIENT_ID", "zerograph");
    expect((await RootPage()).props).toMatchObject({ demo: true, sso: true });
    mocks.currentSession.mockResolvedValue({ accessToken: "t", kind: "oidc" });
    expect((await RootPage()).props.demo).toBe(false);
    vi.stubEnv("ZG_OIDC_ISSUER", "");
    expect((await RootPage()).props.sso).toBe(false);
  });
});

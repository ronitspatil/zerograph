import { afterEach, describe, expect, it, vi } from "vitest";
import { ssoConfigured } from "@/lib/oidc";

describe("ssoConfigured", () => {
  afterEach(() => vi.unstubAllEnvs());
  it("needs both an issuer and a client id", () => {
    vi.stubEnv("ZG_OIDC_ISSUER", "");
    vi.stubEnv("ZG_OIDC_CLIENT_ID", "");
    expect(ssoConfigured()).toBe(false);
    vi.stubEnv("ZG_OIDC_ISSUER", "https://idp.example.test");
    expect(ssoConfigured()).toBe(false);
    vi.stubEnv("ZG_OIDC_CLIENT_ID", "zerograph");
    expect(ssoConfigured()).toBe(true);
    vi.stubEnv("ZG_OIDC_ISSUER", "  ");
    expect(ssoConfigured()).toBe(false);
  });
});

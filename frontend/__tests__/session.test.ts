// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { EncryptJWT } from "jose";
import { seal, unseal, validOrigin } from "@/lib/session";

beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  vi.stubEnv("ZG_ENVIRONMENT", "test");
  vi.stubEnv("ZG_SESSION_SECRET", "s".repeat(64));
  vi.stubEnv("ZG_PUBLIC_URL", "https://console.example/");
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("session encryption", () => {
  it("authenticates encrypted payloads and rejects tampering", async () => {
    const token = await seal({ access_token: "credential" });
    expect(token).not.toContain("credential");
    expect((await unseal(token)).access_token).toBe("credential");
    const parts = token.split(".");
    parts[3] = `${parts[3][0] === "a" ? "b" : "a"}${parts[3].slice(1)}`;
    await expect(unseal(parts.join("."))).rejects.toThrow();
  });
  it("rejects expired cookies", async () => {
    await expect(
      unseal(await seal({ access_token: "credential" }, -60)),
    ).rejects.toThrow();
  });
  it("rejects alternate encryption algorithms even with the correct key", async () => {
    const key = new Uint8Array(
      await webcrypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode("s".repeat(64)),
      ),
    );
    const token = await new EncryptJWT({ access_token: "credential" })
      .setProtectedHeader({ alg: "A256KW", enc: "A256GCM" })
      .setExpirationTime("1h")
      .encrypt(key);
    await expect(unseal(token)).rejects.toThrow();
  });
  it("fails closed on missing secrets and insecure production URLs", async () => {
    vi.stubEnv("ZG_SESSION_SECRET", "short");
    await expect(seal({})).rejects.toThrow();
    vi.stubEnv("ZG_SESSION_SECRET", "s".repeat(64));
    vi.stubEnv("ZG_ENVIRONMENT", "production");
    vi.stubEnv("ZG_PUBLIC_URL", "http://console.example");
    await expect(seal({})).rejects.toThrow();
  });
});
describe("origin validation", () => {
  it("normalizes configured trailing slashes without trusting request host", () => {
    expect(
      validOrigin(
        new Request("https://untrusted.example", {
          headers: { origin: "https://console.example" },
        }),
      ),
    ).toBe(true);
    expect(
      validOrigin(
        new Request("https://console.example", {
          headers: { origin: "https://attacker.example" },
        }),
      ),
    ).toBe(false);
    expect(validOrigin(new Request("https://console.example"))).toBe(false);
  });
  it("rejects invalid configuration", () => {
    vi.stubEnv("ZG_PUBLIC_URL", "invalid");
    expect(
      validOrigin(
        new Request("https://console.example", {
          headers: { origin: "invalid" },
        }),
      ),
    ).toBe(false);
  });
});

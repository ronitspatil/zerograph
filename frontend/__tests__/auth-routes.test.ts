// @vitest-environment node
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  accessToken: vi.fn(),
  validOrigin: vi.fn(),
  seal: vi.fn(),
  unseal: vi.fn(),
  cookieGet: vi.fn(),
}));
vi.mock("@/lib/session", () => ({
  ...mocks,
  sessionCookie: "zg_session",
  cookieOptions: { httpOnly: true, secure: true, sameSite: "lax", path: "/" },
}));
vi.mock("next/headers", () => ({
  cookies: async () => ({ get: mocks.cookieGet }),
}));
import { POST, GET } from "@/app/api/zg/[...path]/route";
import { GET as callback } from "@/app/api/auth/callback/route";
import { discover } from "@/lib/oidc";

const fetchMock = vi.fn();
const discovery = {
  issuer: "https://issuer.example",
  authorization_endpoint: "https://issuer.example/authorize",
  token_endpoint: "https://issuer.example/token",
};
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("ZG_PUBLIC_URL", "https://console.example");
  vi.stubEnv("ZG_BACKEND_URL", "https://backend.example");
  vi.stubEnv("ZG_OIDC_ISSUER", "https://issuer.example");
  mocks.accessToken.mockResolvedValue("credential");
  mocks.validOrigin.mockReturnValue(true);
  mocks.cookieGet.mockReturnValue({ value: "oauth-cookie" });
  mocks.unseal.mockResolvedValue({
    state: "expected",
    verifier: "pkce-verifier",
  });
  mocks.seal.mockResolvedValue("encrypted-session");
  fetchMock.mockReset();
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});
const params = { params: Promise.resolve({ path: ["ingestions"] }) };

it("BFF rejects missing sessions, invalid origins and invalid paths before fetch", async () => {
  mocks.accessToken.mockResolvedValue(null);
  expect(
    (await GET(new Request("https://console.example/api/zg/graph"), params))
      .status,
  ).toBe(401);
  mocks.accessToken.mockResolvedValue("credential");
  mocks.validOrigin.mockReturnValue(false);
  expect(
    (
      await POST(
        new Request("https://console.example", { method: "POST" }),
        params,
      )
    ).status,
  ).toBe(403);
  expect(fetchMock).not.toHaveBeenCalled();
  mocks.validOrigin.mockReturnValue(true);
  expect(
    (
      await GET(new Request("https://console.example"), {
        params: Promise.resolve({ path: [".."] }),
      })
    ).status,
  ).toBe(400);
});
it("BFF rejects a streamed oversized request without forwarding credentials", async () => {
  let cancelled = false;
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(4_000_001));
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://console.example", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit);
  expect((await POST(request, params)).status).toBe(413);
  expect(cancelled).toBe(true);
  expect(fetchMock).not.toHaveBeenCalled();
});
it("BFF forwards only server credentials and rejects upstream redirects", async () => {
  fetchMock.mockResolvedValue(new Response('{"ok":true}', { status: 200 }));
  const response = await POST(
    new Request("https://console.example", {
      method: "POST",
      body: '{"source":"aws"}',
      headers: { Authorization: "Bearer attacker" },
    }),
    params,
  );
  expect(response.status).toBe(200);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(fetchMock).toHaveBeenCalledWith(
    "https://backend.example/api/v1/ingestions",
    expect.objectContaining({
      redirect: "error",
      headers: expect.objectContaining({ Authorization: "Bearer credential" }),
    }),
  );
});
it("OIDC discovery rejects mismatched issuers and credential-bearing endpoints", async () => {
  for (const changes of [
    { issuer: "https://other.example" },
    { token_endpoint: "https://secret@issuer.example/token" },
    { token_endpoint: "http://issuer.example/token" },
  ]) {
    fetchMock.mockResolvedValueOnce(
      Response.json({ ...discovery, ...changes }),
    );
    await expect(discover()).rejects.toThrow();
  }
  expect(fetchMock.mock.calls[0][1].redirect).toBe("error");
});
it("OAuth callback rejects state mismatches without exchanging a code", async () => {
  const response = await callback(
    new Request(
      "https://console.example/api/auth/callback?state=wrong&code=code",
    ),
  );
  expect(response.headers.get("location")).toContain("error=authentication");
  expect(fetchMock).not.toHaveBeenCalled();
});
it("OAuth callback binds PKCE and disallows redirects during credential exchange", async () => {
  fetchMock.mockResolvedValueOnce(Response.json(discovery));
  fetchMock.mockResolvedValueOnce(
    Response.json({ access_token: "verified-token", expires_in: 900 }),
  );
  fetchMock.mockResolvedValueOnce(Response.json({ tenant_id: "tenant-a" }));
  const response = await callback(
    new Request(
      "https://console.example/api/auth/callback?state=expected&code=code",
    ),
  );
  expect(response.headers.get("location")).toBe("https://console.example/");
  const exchange = fetchMock.mock.calls[1][1];
  expect(exchange.redirect).toBe("error");
  expect(exchange.body.get("code_verifier")).toBe("pkce-verifier");
  expect(fetchMock.mock.calls[2][1].redirect).toBe("error");
  expect(mocks.seal).toHaveBeenCalledWith(
    { access_token: "verified-token" },
    900,
  );
  expect(response.headers.get("set-cookie")).toContain("HttpOnly");
});
it("OAuth callback never creates a session for a backend-rejected token", async () => {
  fetchMock.mockResolvedValueOnce(Response.json(discovery));
  fetchMock.mockResolvedValueOnce(
    Response.json({ access_token: "rejected-token" }),
  );
  fetchMock.mockResolvedValueOnce(new Response(null, { status: 403 }));
  expect(
    (
      await callback(
        new Request(
          "https://console.example/api/auth/callback?state=expected&code=code",
        ),
      )
    ).headers.get("location"),
  ).toContain("error=authentication");
  expect(mocks.seal).not.toHaveBeenCalled();
});

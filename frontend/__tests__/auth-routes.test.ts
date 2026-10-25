// @vitest-environment node
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  accessToken: vi.fn(),
  currentSession: vi.fn(),
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
import { POST as logout } from "@/app/api/auth/logout/route";
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
  vi.useRealTimers();
  vi.restoreAllMocks();
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
it("BFF passes through only findings paging headers", async () => {
  fetchMock.mockResolvedValue(
    new Response("[]", {
      status: 200,
      headers: {
        "X-Graph-Revision": "r1",
        "X-Total-Count": "250",
        "X-Next-Cursor": "f0199",
        "Set-Cookie": "upstream=1",
        "X-Internal": "secret",
      },
    }),
  );
  const response = await GET(
    new Request("https://console.example/api/zg/findings?limit=200"),
    { params: Promise.resolve({ path: ["findings"] }) },
  );
  expect(fetchMock).toHaveBeenCalledWith(
    "https://backend.example/api/v1/findings?limit=200",
    expect.anything(),
  );
  expect(response.headers.get("x-graph-revision")).toBe("r1");
  expect(response.headers.get("x-total-count")).toBe("250");
  expect(response.headers.get("x-next-cursor")).toBe("f0199");
  expect(response.headers.get("set-cookie")).toBeNull();
  expect(response.headers.get("x-internal")).toBeNull();
});
it("OIDC discovery rejects mismatched issuers and credential-bearing endpoints", async () => {
  for (const changes of [
    { issuer: "https://other.example" },
    { token_endpoint: "https://secret@issuer.example/token" },
    { token_endpoint: "http://issuer.example/token" },
    { end_session_endpoint: "http://issuer.example/logout" },
    { end_session_endpoint: "https://issuer.example/logout#x" },
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
    { access_token: "verified-token", kind: "oidc" },
    900,
  );
  expect(response.headers.get("set-cookie")).toContain("HttpOnly");
});
it("OAuth callback keeps the ID token as a sign-out hint only while the cookie fits", async () => {
  for (const [sealed, kept] of [
    ["x".repeat(3000), true],
    ["x".repeat(5000), false],
  ] as const) {
    mocks.seal.mockReset();
    mocks.seal
      .mockResolvedValueOnce("small-session")
      .mockResolvedValueOnce(sealed);
    fetchMock.mockReset();
    fetchMock.mockResolvedValueOnce(Response.json(discovery));
    fetchMock.mockResolvedValueOnce(
      Response.json({ access_token: "verified-token", id_token: "id-token" }),
    );
    fetchMock.mockResolvedValueOnce(Response.json({ tenant_id: "tenant-a" }));
    const response = await callback(
      new Request(
        "https://console.example/api/auth/callback?state=expected&code=code",
      ),
    );
    expect(mocks.seal).toHaveBeenLastCalledWith(
      { access_token: "verified-token", kind: "oidc", id_token: "id-token" },
      3600,
    );
    expect(response.headers.get("set-cookie")).toContain(
      `zg_session=${kept ? sealed : "small-session"};`,
    );
  }
});
it("logout ends an organization session at the provider and returns to sign-in", async () => {
  vi.stubEnv("ZG_OIDC_CLIENT_ID", "zerograph-web");
  mocks.currentSession.mockResolvedValue({
    accessToken: "credential",
    kind: "oidc",
    idToken: "id-token",
  });
  fetchMock.mockResolvedValueOnce(
    Response.json({
      ...discovery,
      end_session_endpoint: "https://issuer.example/logout",
    }),
  );
  const response = await logout(
    new Request("https://console.example/api/auth/logout", { method: "POST" }),
  );
  const { redirect } = await response.json();
  const url = new URL(redirect);
  expect(url.origin + url.pathname).toBe("https://issuer.example/logout");
  expect(url.searchParams.get("id_token_hint")).toBe("id-token");
  expect(url.searchParams.get("client_id")).toBe("zerograph-web");
  expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
    "https://console.example/login",
  );
  expect(response.headers.get("set-cookie")).toMatch(/zg_session=;/);
});
it("logout of a demo session or without a provider endpoint stays local", async () => {
  mocks.currentSession.mockResolvedValue({
    accessToken: "credential",
    kind: "demo",
  });
  let response = await logout(
    new Request("https://console.example/api/auth/logout", { method: "POST" }),
  );
  expect(await response.json()).toEqual({ ok: true });
  expect(fetchMock).not.toHaveBeenCalled();
  mocks.currentSession.mockResolvedValue({
    accessToken: "credential",
    kind: "oidc",
    idToken: "id-token",
  });
  fetchMock.mockResolvedValueOnce(Response.json(discovery));
  response = await logout(
    new Request("https://console.example/api/auth/logout", { method: "POST" }),
  );
  expect(await response.json()).toEqual({ ok: true });
  expect(response.headers.get("set-cookie")).toMatch(/zg_session=;/);
  mocks.validOrigin.mockReturnValue(false);
  expect(
    (
      await logout(
        new Request("https://console.example/api/auth/logout", {
          method: "POST",
        }),
      )
    ).status,
  ).toBe(403);
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

it("BFF uses one bounded buffer for many tiny body chunks", async () => {
  const allocation = vi.spyOn(Buffer, "alloc");
  let sent = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (sent++ < 10_000) controller.enqueue(new Uint8Array([120]));
      else controller.close();
    },
  });
  fetchMock.mockResolvedValue(Response.json({ ok: true }));
  const request = new Request("https://console.example", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit);
  expect((await POST(request, params)).status).toBe(200);
  expect(
    allocation.mock.calls.filter(([size]) => size === 4_000_000),
  ).toHaveLength(1);
  const forwarded = fetchMock.mock.calls[0][1].body;
  expect(forwarded.byteLength).toBe(10_000);
  expect(forwarded.every((byte: number) => byte === 120)).toBe(true);
});
it("BFF cancels stalled request bodies at the total read deadline", async () => {
  vi.useFakeTimers();
  let cancelled = false;
  const stream = new ReadableStream({
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://console.example", {
    method: "POST",
    body: stream,
    duplex: "half",
  } as RequestInit);
  const response = POST(request, params);
  await vi.advanceTimersByTimeAsync(30_000);
  expect((await response).status).toBe(408);
  expect(cancelled).toBe(true);
  expect(fetchMock).not.toHaveBeenCalled();
});

import { afterEach, expect, it, vi } from "vitest";
import { api, ApiError } from "@/lib/api";
afterEach(() => vi.unstubAllGlobals());
it("uses the same-origin proxy without client bearer tokens", async () => {
  const fetch = vi
    .fn()
    .mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    );
  vi.stubGlobal("fetch", fetch);
  await expect(api("graph")).resolves.toEqual({ ok: true });
  expect(fetch.mock.calls[0][0]).toBe("/api/zg/graph");
  expect(fetch.mock.calls[0][1].headers.Authorization).toBeUndefined();
});
it("preserves backend authorization errors", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ detail: "analyst role required" }), {
        status: 403,
      }),
    ),
  );
  await expect(api("simulate")).rejects.toEqual(
    new ApiError("analyst role required", 403),
  );
});

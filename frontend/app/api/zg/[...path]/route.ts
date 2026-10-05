import { NextResponse } from "next/server";
import { accessToken, validOrigin } from "@/lib/session";
export const dynamic = "force-dynamic";
const pagingHeaders = ["X-Graph-Revision", "X-Total-Count", "X-Next-Cursor"];
async function proxy(
  request: Request,
  { params }: { params: Promise<{ path: string[] }> },
) {
  if (request.method !== "GET" && !validOrigin(request))
    return NextResponse.json({ detail: "Invalid origin" }, { status: 403 });
  const { path } = await params;
  const token = await accessToken();
  if (!token)
    return NextResponse.json(
      { detail: "Session expired. Sign in again." },
      { status: 401 },
    );
  if (path.some((p) => !/^[-a-zA-Z0-9_]+$/.test(p)))
    return NextResponse.json({ detail: "Invalid path" }, { status: 400 });
  const base = process.env.ZG_BACKEND_URL;
  if (!base)
    return NextResponse.json(
      { detail: "Backend is not configured" },
      { status: 503 },
    );
  try {
    // Reject as bytes arrive instead of buffering an unbounded chunked body.
    let body: Uint8Array | undefined;
    if (request.method !== "GET" && request.body) {
      const reader = request.body.getReader();
      const buffer = Buffer.alloc(4_000_000);
      let size = 0;
      let timedOut = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          reject(new Error("Request body timed out"));
        }, 30_000);
      });
      try {
        const readBody = async () => {
          while (true) {
            const chunk = await reader.read();
            if (chunk.done) return true;
            size += chunk.value.byteLength;
            if (size > buffer.byteLength) {
              void reader.cancel().catch(() => {});
              return false;
            }
            buffer.set(chunk.value, size - chunk.value.byteLength);
          }
        };
        if (!(await Promise.race([readBody(), deadline]))) {
          return NextResponse.json(
            { detail: "Payload too large" },
            { status: 413 },
          );
        }
      } catch (error) {
        void reader.cancel().catch(() => {});
        if (timedOut) {
          return NextResponse.json(
            { detail: "Request body timed out" },
            { status: 408 },
          );
        }
        throw error;
      } finally {
        clearTimeout(timer);
        reader.releaseLock();
      }
      body = buffer.subarray(0, size);
    }
    const upstream = await fetch(
      `${base}/api/v1/${path.join("/")}${new URL(request.url).search}`,
      {
        method: request.method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: body as BodyInit | undefined,
        cache: "no-store",
        signal: AbortSignal.timeout(30000),
        redirect: "error",
      },
    );
    const headers = new Headers({
      "Content-Type":
        upstream.headers.get("Content-Type") || "application/json",
      "Cache-Control": "no-store",
    });
    // Only the documented findings paging headers pass through.
    for (const name of pagingHeaders) {
      const value = upstream.headers.get(name);
      if (value !== null) headers.set(name, value);
    }
    return new NextResponse(await upstream.text(), {
      status: upstream.status,
      headers,
    });
  } catch {
    return NextResponse.json(
      { detail: "Backend unavailable. Try again shortly." },
      { status: 503 },
    );
  }
}
export { proxy as GET, proxy as POST, proxy as PUT };

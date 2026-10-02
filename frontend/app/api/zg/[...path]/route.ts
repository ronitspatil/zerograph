import { NextResponse } from "next/server";
import { accessToken, validOrigin } from "@/lib/session";
export const dynamic = "force-dynamic";
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
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          size += chunk.value.byteLength;
          if (size > 4_000_000) {
            await reader.cancel();
            return NextResponse.json(
              { detail: "Payload too large" },
              { status: 413 },
            );
          }
          chunks.push(chunk.value);
        }
      } finally {
        reader.releaseLock();
      }
      body = Buffer.concat(chunks, size);
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
    return new NextResponse(await upstream.text(), {
      status: upstream.status,
      headers: {
        "Content-Type":
          upstream.headers.get("Content-Type") || "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch {
    return NextResponse.json(
      { detail: "Backend unavailable. Try again shortly." },
      { status: 503 },
    );
  }
}
export { proxy as GET, proxy as POST };

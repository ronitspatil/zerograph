import { NextResponse } from "next/server";
import { cookieOptions, seal, sessionCookie, validOrigin } from "@/lib/session";
export async function POST(request: Request) {
  if (!validOrigin(request))
    return NextResponse.json({ detail: "Invalid origin" }, { status: 403 });
  if (process.env.ZG_DEMO_MODE !== "true" || !process.env.ZG_DEMO_TOKEN)
    return NextResponse.json({ detail: "Demo disabled" }, { status: 403 });
  const response = NextResponse.json({ ok: true });
  response.cookies.set(
    sessionCookie,
    await seal({ access_token: process.env.ZG_DEMO_TOKEN }),
    { ...cookieOptions, maxAge: 3600 },
  );
  return response;
}

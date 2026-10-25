import { NextResponse } from "next/server";
import { cookieOptions, sessionCookie, validOrigin } from "@/lib/session";
import { demoSession, demoSessionSeconds } from "@/lib/demo";
export async function POST(request: Request) {
  if (!validOrigin(request))
    return NextResponse.json({ detail: "Invalid origin" }, { status: 403 });
  const sealed = await demoSession();
  if (!sealed)
    return NextResponse.json({ detail: "Demo disabled" }, { status: 403 });
  const response = NextResponse.json({ ok: true });
  response.cookies.set(sessionCookie, sealed, {
    ...cookieOptions,
    maxAge: demoSessionSeconds,
  });
  return response;
}

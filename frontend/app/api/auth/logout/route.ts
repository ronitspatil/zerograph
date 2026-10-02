import { NextResponse } from "next/server";
import { sessionCookie, validOrigin } from "@/lib/session";
export async function POST(request: Request) {
  if (!validOrigin(request))
    return NextResponse.json({ detail: "Invalid origin" }, { status: 403 });
  const response = NextResponse.json({ ok: true });
  response.cookies.delete(sessionCookie);
  return response;
}

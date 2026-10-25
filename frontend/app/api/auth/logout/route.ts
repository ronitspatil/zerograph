import { NextResponse } from "next/server";
import { currentSession, sessionCookie, validOrigin } from "@/lib/session";
import { discover } from "@/lib/oidc";
export const dynamic = "force-dynamic";
export async function POST(request: Request) {
  if (!validOrigin(request))
    return NextResponse.json({ detail: "Invalid origin" }, { status: 403 });
  const session = await currentSession();
  let redirect: string | undefined;
  if (session?.kind === "oidc" && session.idToken) {
    try {
      // RP-initiated logout ends the provider session too, so the next "Sign in with
      // your organization" asks for credentials again instead of silently reusing it.
      const { end_session_endpoint } = await discover();
      if (end_session_endpoint) {
        const url = new URL(end_session_endpoint);
        url.searchParams.set("id_token_hint", session.idToken);
        url.searchParams.set("client_id", process.env.ZG_OIDC_CLIENT_ID || "");
        url.searchParams.set(
          "post_logout_redirect_uri",
          `${process.env.ZG_PUBLIC_URL}/login`,
        );
        redirect = url.toString();
      }
    } catch {
      // The local session still ends; the provider session simply outlives it.
    }
  }
  const response = NextResponse.json(
    redirect ? { ok: true, redirect } : { ok: true },
  );
  response.cookies.delete(sessionCookie);
  return response;
}

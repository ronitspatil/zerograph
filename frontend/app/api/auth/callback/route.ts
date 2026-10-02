import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { cookieOptions, seal, sessionCookie, unseal } from "@/lib/session";
import { discover } from "@/lib/oidc";
export const dynamic = "force-dynamic";
export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const cookie = (await cookies()).get("zg_oauth")?.value;
    if (!cookie) throw new Error("Missing state");
    const state = await unseal(cookie);
    if (
      !url.searchParams.get("state") ||
      state.state !== url.searchParams.get("state") ||
      !url.searchParams.get("code")
    )
      throw new Error("Invalid state");
    const { token_endpoint } = await discover();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: url.searchParams.get("code")!,
      redirect_uri: `${process.env.ZG_PUBLIC_URL}/api/auth/callback`,
      client_id: process.env.ZG_OIDC_CLIENT_ID || "",
      code_verifier: String(state.verifier),
    });
    if (process.env.ZG_OIDC_CLIENT_SECRET)
      body.set("client_secret", process.env.ZG_OIDC_CLIENT_SECRET);
    const exchange = await fetch(token_endpoint, {
      method: "POST",
      body,
      signal: AbortSignal.timeout(10000),
    });
    if (!exchange.ok) throw new Error("Exchange failed");
    const tokens = await exchange.json();
    if (typeof tokens.access_token !== "string")
      throw new Error("Missing access token");
    // Backend verifies signature, issuer, audience, tenant and roles on the access token.
    const actor = await fetch(`${process.env.ZG_BACKEND_URL}/api/v1/me`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
    });
    if (!actor.ok) throw new Error("Token is not authorized for ZeroGraph");
    const maxAge = Math.max(
      1,
      Math.min(Number(tokens.expires_in) || 3600, 3600),
    );
    const response = NextResponse.redirect(`${process.env.ZG_PUBLIC_URL}/`);
    response.cookies.set(
      sessionCookie,
      await seal({ access_token: tokens.access_token }, maxAge),
      { ...cookieOptions, maxAge },
    );
    response.cookies.delete("zg_oauth");
    return response;
  } catch {
    const response = NextResponse.redirect(
      `${process.env.ZG_PUBLIC_URL}/login?error=authentication`,
    );
    response.cookies.delete("zg_oauth");
    return response;
  }
}

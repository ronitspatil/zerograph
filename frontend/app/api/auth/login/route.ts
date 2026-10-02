import { NextResponse } from "next/server";
import { cookieOptions, seal } from "@/lib/session";
import { discover } from "@/lib/oidc";
export const dynamic = "force-dynamic";
export async function GET() {
  try {
    const { authorization_endpoint } = await discover();
    const verifier = Buffer.from(
      crypto.getRandomValues(new Uint8Array(32)),
    ).toString("base64url");
    const challenge = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    ).toString("base64url");
    const state = crypto.randomUUID();
    const url = new URL(authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: process.env.ZG_OIDC_CLIENT_ID || "",
      response_type: "code",
      scope: process.env.ZG_OIDC_SCOPE || "openid profile",
      redirect_uri: `${process.env.ZG_PUBLIC_URL}/api/auth/callback`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
    }).toString();
    const response = NextResponse.redirect(url);
    response.cookies.set("zg_oauth", await seal({ verifier, state }, 600), {
      ...cookieOptions,
      maxAge: 600,
    });
    return response;
  } catch {
    return NextResponse.redirect(
      `${process.env.ZG_PUBLIC_URL}/login?error=configuration`,
    );
  }
}

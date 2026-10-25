import { NextResponse, type NextRequest } from "next/server";
import { cookieOptions, sessionCookie, unseal } from "@/lib/session";
import { demoEnabled, demoSession, demoSessionSeconds } from "@/lib/demo";
async function signedIn(request: NextRequest): Promise<boolean> {
  const cookie = request.cookies.get(sessionCookie)?.value;
  if (!cookie) return false;
  try {
    return typeof (await unseal(cookie)).access_token === "string";
  } catch {
    return false;
  }
}
async function mintDemo(): Promise<string | null> {
  try {
    return await demoSession();
  } catch {
    // Misconfigured secrets: no session, so the sign-in page explains instead of looping.
    return null;
  }
}
function setSession(response: NextResponse, sealed: string) {
  response.cookies.set(sessionCookie, sealed, {
    ...cookieOptions,
    maxAge: demoSessionSeconds,
  });
}
/**
 * Demo deployments open straight on the console: a visit without a valid session gets a
 * demo session here, before the page renders, so no sign-in page is ever shown in between.
 * /login then returns to the dashboard (app/login/page.tsx) unless it is showing a single
 * sign-on error. Outside demo mode this never creates a session.
 */
async function demoLanding(request: NextRequest): Promise<string | null> {
  const { pathname, searchParams } = request.nextUrl;
  if (pathname !== "/" && pathname !== "/login") return null;
  if (pathname === "/login" && searchParams.has("error")) return null;
  if (!demoEnabled() || (await signedIn(request))) return null;
  return mintDemo();
}
export async function middleware(request: NextRequest) {
  const sealed = await demoLanding(request);
  const nonce = btoa(crypto.randomUUID());
  const dev = process.env.NODE_ENV !== "production";
  const csp = `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'${dev ? " ws:" : ""}; worker-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`;
  if (sealed) request.cookies.set(sessionCookie, sealed);
  const headers = new Headers(request.headers);
  headers.set("x-nonce", nonce);
  headers.set("Content-Security-Policy", csp);
  // The page renders with the new demo session, which the browser keeps from here on.
  if (sealed)
    headers.set(
      "cookie",
      request.cookies
        .getAll()
        .map((c) => `${c.name}=${c.value}`)
        .join("; "),
    );
  const response = NextResponse.next({ request: { headers } });
  response.headers.set("Content-Security-Policy", csp);
  if (sealed) setSession(response, sealed);
  return response;
}
export const config = {
  // Icons and the web manifest are static and need no per-request CSP nonce.
  matcher: [
    "/((?!api|_next/static|_next/image|favicon\\.ico|favicon\\.svg|apple-touch-icon\\.png|icon-\\d+\\.png|manifest\\.webmanifest).*)",
  ],
};

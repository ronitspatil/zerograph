import { EncryptJWT, jwtDecrypt } from "jose";
import { cookies } from "next/headers";
export const sessionCookie = "zg_session";
export const secureCookie = process.env.ZG_COOKIE_SECURE !== "false";
function key() {
  if (
    process.env.ZG_ENVIRONMENT === "production" &&
    (!secureCookie || !process.env.ZG_PUBLIC_URL?.startsWith("https://"))
  ) {
    throw new Error("Production requires HTTPS and secure session cookies");
  }
  const value = process.env.ZG_SESSION_SECRET;
  if (!value || value.length < 32)
    throw new Error("ZG_SESSION_SECRET must be at least 32 characters");
  // SHA-256 gives a fixed AES key while allowing a generated hex/base64 environment secret.
  return crypto.subtle
    .digest("SHA-256", new TextEncoder().encode(value))
    .then((b) => new Uint8Array(b));
}
export async function seal(payload: Record<string, unknown>, seconds = 3600) {
  return new EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(`${seconds}s`)
    .encrypt(await key());
}
export async function unseal(token: string) {
  return (
    await jwtDecrypt(token, await key(), {
      clockTolerance: 10,
      keyManagementAlgorithms: ["dir"],
      contentEncryptionAlgorithms: ["A256GCM"],
    })
  ).payload;
}
/** The sealed session: its access token, how it was created and, for OIDC, the ID token for sign-out. */
export async function currentSession(): Promise<{
  accessToken: string;
  kind?: "demo" | "oidc";
  idToken?: string;
} | null> {
  const cookie = (await cookies()).get(sessionCookie)?.value;
  if (!cookie) return null;
  try {
    const payload = await unseal(cookie);
    if (typeof payload.access_token !== "string") return null;
    return {
      accessToken: payload.access_token,
      kind:
        payload.kind === "demo" || payload.kind === "oidc"
          ? payload.kind
          : undefined,
      idToken:
        typeof payload.id_token === "string" ? payload.id_token : undefined,
    };
  } catch {
    return null;
  }
}
export async function accessToken(): Promise<string | null> {
  return (await currentSession())?.accessToken ?? null;
}
export const cookieOptions = {
  httpOnly: true,
  secure: secureCookie,
  sameSite: "lax" as const,
  path: "/",
};
export function validOrigin(request: Request): boolean {
  const configured = process.env.ZG_PUBLIC_URL;
  if (!configured) return false;
  try {
    const publicURL = new URL(configured);
    return (
      ["https:", "http:"].includes(publicURL.protocol) &&
      !publicURL.username &&
      !publicURL.password &&
      request.headers.get("origin") === publicURL.origin
    );
  } catch {
    return false;
  }
}

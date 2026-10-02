interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
}
export async function discover(): Promise<Discovery> {
  const issuer = process.env.ZG_OIDC_ISSUER;
  if (!issuer?.startsWith("https://"))
    throw new Error("Configure an HTTPS OIDC issuer");
  const response = await fetch(
    `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
    { cache: "no-store", redirect: "error", signal: AbortSignal.timeout(8000) },
  );
  if (!response.ok) throw new Error("OIDC discovery failed");
  const body = await response.json();
  if (body.issuer !== issuer) throw new Error("OIDC issuer mismatch");
  for (const endpoint of [body.authorization_endpoint, body.token_endpoint]) {
    const url = new URL(endpoint);
    if (url.protocol !== "https:" || url.username || url.password || url.hash)
      throw new Error("Invalid OIDC discovery document");
  }
  return body;
}

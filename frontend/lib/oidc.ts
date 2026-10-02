interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
}
export async function discover(): Promise<Discovery> {
  const issuer = process.env.ZG_OIDC_ISSUER;
  if (!issuer?.startsWith("https://"))
    throw new Error("Configure an HTTPS OIDC issuer");
  const response = await fetch(
    `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`,
    { cache: "no-store", signal: AbortSignal.timeout(8000) },
  );
  if (!response.ok) throw new Error("OIDC discovery failed");
  const body = await response.json();
  for (const endpoint of [body.authorization_endpoint, body.token_endpoint]) {
    if (typeof endpoint !== "string" || !endpoint.startsWith("https://"))
      throw new Error("Invalid OIDC discovery document");
  }
  return body;
}

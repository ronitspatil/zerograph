import { redirect } from "next/navigation";
import { Login } from "@/components/login";
import { ssoConfigured } from "@/lib/oidc";
import { demoEnabled } from "@/lib/demo";
import { currentSession } from "@/lib/session";
export const dynamic = "force-dynamic";
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  // A demo deployment opens on the dashboard (the middleware has already given this
  // visit a demo session); /login stays to explain single sign-on errors.
  if (!error && demoEnabled() && (await currentSession())) redirect("/");
  return (
    <Login
      demo={process.env.ZG_DEMO_MODE === "true"}
      sso={ssoConfigured()}
      error={error}
    />
  );
}

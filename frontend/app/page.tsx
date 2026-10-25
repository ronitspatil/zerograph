import { redirect } from "next/navigation";
import { currentSession } from "@/lib/session";
import { Console } from "@/components/console";
import { ssoConfigured } from "@/lib/oidc";
export const dynamic = "force-dynamic";
export default async function Page() {
  const session = await currentSession();
  if (!session) redirect("/login");
  // A demo deployment can also offer SSO: an organization session is never shown as the demo.
  return (
    <Console
      demo={process.env.ZG_DEMO_MODE === "true" && session.kind !== "oidc"}
      sso={ssoConfigured()}
    />
  );
}

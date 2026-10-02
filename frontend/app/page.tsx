import { redirect } from "next/navigation";
import { accessToken } from "@/lib/session";
import { Console } from "@/components/console";
export const dynamic = "force-dynamic";
export default async function Page() {
  if (!(await accessToken())) redirect("/login");
  return <Console demo={process.env.ZG_DEMO_MODE === "true"} />;
}

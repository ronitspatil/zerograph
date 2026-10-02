import { Login } from "@/components/login";
export const dynamic = "force-dynamic";
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  return <Login demo={process.env.ZG_DEMO_MODE === "true"} error={error} />;
}

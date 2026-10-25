import { seal } from "@/lib/session";
/** Seconds a demo session lasts; the demo landing mints a fresh one after that. */
export const demoSessionSeconds = 3600;
/**
 * The demo workspace is offered only when the deployment is in demo mode and has a demo
 * token. Nothing else ever creates a session without signing in.
 */
export function demoEnabled(): boolean {
  return process.env.ZG_DEMO_MODE === "true" && !!process.env.ZG_DEMO_TOKEN;
}
/** A sealed demo session cookie value, or null when the demo is off. */
export async function demoSession(): Promise<string | null> {
  if (!demoEnabled()) return null;
  return seal(
    { access_token: process.env.ZG_DEMO_TOKEN, kind: "demo" },
    demoSessionSeconds,
  );
}

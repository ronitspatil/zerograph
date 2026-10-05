"use client";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Wordmark } from "@/components/ui/logo";
export function Login({ demo, error }: { demo: boolean; error?: string }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(
    error ? "Sign-in failed. Check your identity provider configuration." : "",
  );
  async function enter() {
    setBusy(true);
    try {
      const r = await fetch("/api/auth/demo", { method: "POST" });
      if (!r.ok) throw new Error("Demo sign-in unavailable");
      window.location.assign("/");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Sign-in failed");
      setBusy(false);
    }
  }
  return (
    <main className="login-shell">
      <div className="login-card">
        <Wordmark size={32} className="login-wordmark" />
        <div className="login-body">
          <h1>Sign in</h1>
          <p>Continue with your organization&rsquo;s identity provider.</p>
          {message && (
            <p className="error-banner" role="alert">
              {message}
            </p>
          )}
          <div className="login-actions">
            <Button asChild>
              <a href="/api/auth/login">Sign in with your organization</a>
            </Button>
            {demo && (
              <Button variant="outline" onClick={enter} disabled={busy}>
                {busy ? "Opening console…" : "Explore the demo workspace"}
              </Button>
            )}
          </div>
        </div>
      </div>
      <div className="login-orbit" aria-hidden="true" />
    </main>
  );
}

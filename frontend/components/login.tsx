"use client";
import { useState } from "react";
import { GitPullRequest, KeyRound, Route } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Wordmark } from "@/components/ui/logo";
const capabilities = [
  {
    icon: KeyRound,
    text: "Maps people, roles and AI agents to your data",
  },
  { icon: Route, text: "Traces toxic paths from exposed entry points" },
  { icon: GitPullRequest, text: "Proposes least-privilege fixes for review" },
];
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
        <div className="login-intro">
          <Wordmark size={28} className="login-wordmark" />
          <p className="login-lead">
            See who and what can reach your sensitive data.
          </p>
          <ul className="login-points">
            {capabilities.map(({ icon: Icon, text }) => (
              <li key={text}>
                <Icon size={15} aria-hidden="true" />
                {text}
              </li>
            ))}
          </ul>
        </div>
        <div className="login-body">
          <h1>Sign in</h1>
          <p>
            Single sign-on through your organization&rsquo;s identity provider
            (OIDC).
          </p>
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
          <p className="login-help">
            Need access? Contact your workspace administrator.
          </p>
        </div>
      </div>
      <div className="login-orbit" aria-hidden="true" />
    </main>
  );
}

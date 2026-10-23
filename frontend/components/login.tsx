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
export function Login({
  demo,
  sso = true,
  error,
}: {
  demo: boolean;
  /** An OIDC issuer and client are configured; otherwise the SSO button is hidden. */
  sso?: boolean;
  error?: string;
}) {
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
          <h1>{sso || !demo ? "Sign in" : "Explore ZeroGraph"}</h1>
          <p>
            {sso
              ? "Single sign-on through your organization\u2019s identity provider (OIDC)."
              : demo
                ? "A demo workspace with a sample environment. No sign-in needed."
                : "Single sign-on through your organization\u2019s identity provider (OIDC)."}
          </p>
          {message && (
            <p className="error-banner" role="alert">
              {message}
            </p>
          )}
          <div className="login-actions">
            {sso && (
              <Button asChild>
                <a href="/api/auth/login">Sign in with your organization</a>
              </Button>
            )}
            {demo && (
              <Button
                variant={sso ? "outline" : "default"}
                onClick={enter}
                disabled={busy}
              >
                {busy ? "Opening console…" : "Explore the demo workspace"}
              </Button>
            )}
            {!sso && !demo && (
              <p className="login-unconfigured" role="status">
                Single sign-on isn&rsquo;t configured — ask your administrator.
              </p>
            )}
          </div>
          <p className="login-help">
            {sso || !demo
              ? "Need access? Contact your workspace administrator."
              : "Single sign-on appears here once your administrator configures it."}
          </p>
        </div>
      </div>
      <div className="login-orbit" aria-hidden="true" />
    </main>
  );
}

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
const ssoUnconfigured =
  "Single sign-on isn\u2019t configured \u2014 ask your administrator.";
const errors: Record<string, string> = {
  configuration:
    "Single sign-on couldn\u2019t start. Check the identity provider configuration.",
  authentication:
    "Sign-in failed. Your account may not have access to ZeroGraph \u2014 ask your administrator.",
};
export function Login({
  demo,
  sso = true,
  error,
}: {
  demo: boolean;
  /** An OIDC issuer and client are configured. Otherwise the SSO button explains why it can't start. */
  sso?: boolean;
  error?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(
    error
      ? (errors[error] ??
          "Sign-in failed. Check your identity provider configuration.")
      : "",
  );
  // Without OIDC settings the SSO button never silently does nothing: it reveals why.
  // Outside demo mode it is the only way in, so the explanation shows straight away.
  const [ssoNotice, setSsoNotice] = useState(!sso && !demo);
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
  // The demo stays the main action in demo mode; otherwise organization sign-in is.
  const ssoVariant = demo ? "outline" : "default";
  const organization = sso ? (
    <Button asChild variant={ssoVariant}>
      <a href="/api/auth/login">Sign in with your organization</a>
    </Button>
  ) : (
    <Button
      variant={ssoVariant}
      onClick={() => setSsoNotice(true)}
      aria-describedby={ssoNotice ? "login-sso-notice" : undefined}
    >
      Sign in with your organization
    </Button>
  );
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
            {sso || !demo
              ? "Single sign-on through your organization\u2019s identity provider (OIDC)."
              : "A demo workspace with a sample environment. No sign-in needed."}
          </p>
          {message && (
            <p className="error-banner" role="alert">
              {message}
            </p>
          )}
          <div className="login-actions">
            {demo && (
              <Button variant="default" onClick={enter} disabled={busy}>
                {busy ? "Opening console\u2026" : "Explore the demo workspace"}
              </Button>
            )}
            {organization}
            {ssoNotice && (
              <p
                id="login-sso-notice"
                className="login-unconfigured"
                role="status"
              >
                {ssoUnconfigured}
              </p>
            )}
          </div>
          {sso || !demo ? (
            <p className="login-help">
              Need access? Contact your workspace administrator.
            </p>
          ) : (
            !ssoNotice && (
              <p className="login-help">
                Organization sign-in works once your administrator configures
                OIDC.
              </p>
            )
          )}
        </div>
      </div>
      <LoginRing />
    </main>
  );
}

const RING_R = 466;
const RING_C = 2 * Math.PI * RING_R;
const TICK_R = 498;
const TICK_GAP = (2 * Math.PI * TICK_R) / 72;

/**
 * The backdrop ring, drawn like the console's gauges: a hairline outer edge, a tick
 * ring, a track band with an accent arc, and an inner hairline. It sits behind the
 * card, a little left of and below the card's centre, wide enough that the card never
 * touches it.
 */
function LoginRing() {
  return (
    <svg
      className="login-ring"
      viewBox="-550 -550 1100 1100"
      aria-hidden="true"
      focusable="false"
    >
      <circle className="login-ring-glow" r="456" />
      <circle className="login-ring-edge" r="524" />
      <circle
        className="login-ring-ticks"
        r={TICK_R}
        strokeDasharray={`1 ${TICK_GAP - 1}`}
      />
      <circle className="login-ring-track" r={RING_R} />
      <circle
        className="login-ring-arc"
        r={RING_R}
        strokeDasharray={`${RING_C * 0.28} ${RING_C}`}
        style={{ ["--ring-c" as string]: RING_C }}
      />
      <circle className="login-ring-inner" r="432" />
    </svg>
  );
}

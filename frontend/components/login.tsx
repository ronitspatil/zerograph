"use client";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { LogoMark } from "@/components/ui/logo";

/** Decorative node graph behind the login header; the mark sits at its hub. */
const hub = [210, 68] as const;
const nodes: [number, number, boolean][] = [
  [128, 44, true],
  [62, 92, false],
  [32, 30, false],
  [84, 162, true],
  [28, 196, false],
  [292, 38, false],
  [358, 82, true],
  [392, 24, false],
  [342, 158, false],
  [396, 198, true],
];
const edges: [number, number][] = [
  [-1, 0],
  [0, 2],
  [0, 1],
  [1, 2],
  [1, 3],
  [3, 4],
  [-1, 5],
  [5, 7],
  [5, 6],
  [6, 7],
  [6, 8],
  [8, 9],
];
function point(i: number) {
  return i < 0 ? hub : nodes[i];
}
function GraphMotif() {
  return (
    <svg
      className="login-motif"
      viewBox="0 0 420 224"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden="true"
      focusable="false"
    >
      <g className="login-motif-edges">
        {edges.map(([a, b]) => (
          <line
            key={`${a}-${b}`}
            x1={point(a)[0]}
            y1={point(a)[1]}
            x2={point(b)[0]}
            y2={point(b)[1]}
          />
        ))}
      </g>
      {nodes.map(([x, y, lit], i) => (
        <circle
          key={i}
          cx={x}
          cy={y}
          r={lit ? 3 : 2.5}
          className={lit ? "login-motif-node lit" : "login-motif-node"}
          style={lit ? { animationDelay: `${i * 0.45}s` } : undefined}
        />
      ))}
    </svg>
  );
}

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
        <header className="login-header">
          <GraphMotif />
          <LogoMark size={56} className="login-mark" />
          <span className="login-name">ZeroGraph</span>
          <span className="login-tagline">
            Identity and data access security
          </span>
        </header>
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
        <p className="login-footer">Access is scoped by your workspace role.</p>
      </div>
      <div className="login-orbit" aria-hidden="true" />
    </main>
  );
}

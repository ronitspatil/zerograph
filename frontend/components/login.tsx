"use client";
import { useState } from "react";
import { ArrowRight, Network, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
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
        <div className="brand">
          <div className="brand-mark">
            <Network size={24} />
          </div>
          ZeroGraph<span className="beta">PLATFORM</span>
        </div>
        <span className="eyebrow">IDENTITY × DATA SECURITY</span>
        <h1>
          Every identity.
          <br />
          Every access path.
        </h1>
        <p>
          Find the permissions that put your data at risk. Turn complex access
          relationships into decisions you can act on.
        </p>
        <div className="login-graph">
          <span>AI AGENT</span>
          <i />
          <span>CLOUD ROLE</span>
          <i />
          <span>SENSITIVE DATA</span>
        </div>
        {message && (
          <p className="error-banner" role="alert">
            {message}
          </p>
        )}
        <Button asChild>
          <a href="/api/auth/login">
            Sign in with your organization
            <ArrowRight size={16} />
          </a>
        </Button>
        {demo && (
          <Button variant="outline" onClick={enter} disabled={busy}>
            {busy ? "Opening console…" : "Explore the demo workspace"}
            <ArrowRight size={16} />
          </Button>
        )}
        <small>
          <ShieldCheck size={14} /> Tenant-isolated access · Reviewable
          remediation
        </small>
      </div>
      <div className="login-orbit" aria-hidden="true" />
    </main>
  );
}

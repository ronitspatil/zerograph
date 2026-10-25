"use client";
import { useEffect, useRef, useState, type CSSProperties } from "react";
import { LogIn, X } from "lucide-react";
export const ssoUnconfigured =
  "Single sign-on isn’t configured — ask your administrator.";
/**
 * The demo workspace's way into a real organization, at the bottom of the sidebar. With
 * single sign-on configured it is a link that starts the OIDC flow in one click. Without
 * it, it never does nothing: it opens a notice next to the button that says why.
 */
export function SidebarSignIn({ sso, rail }: { sso: boolean; rail: boolean }) {
  const [notice, setNotice] = useState<CSSProperties | null>(null);
  const button = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!notice) return;
    const close = () => setNotice(null);
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      close();
      button.current?.focus();
    };
    const onPointer = (e: PointerEvent) => {
      const target = e.target as Node;
      if (!panel.current?.contains(target) && !button.current?.contains(target))
        close();
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("pointerdown", onPointer);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("pointerdown", onPointer);
      window.removeEventListener("resize", close);
    };
  }, [notice]);
  const title = rail ? "Sign in" : undefined;
  if (sso)
    return (
      <a
        className="nav-item sign-in"
        href="/api/auth/login"
        title={title}
        aria-label="Sign in with your organization"
      >
        <LogIn size={16} aria-hidden="true" />
        <span className="nav-text">Sign in</span>
      </a>
    );
  function toggle() {
    if (notice) return setNotice(null);
    const rect = button.current?.getBoundingClientRect();
    if (!rect) return setNotice({});
    // The sidebar scrolls, so the notice is placed against the viewport: above the
    // button in the full sidebar, beside it on the icon rail (also the phone layout).
    const iconOnly = rect.width < 120;
    const edge =
      button.current?.closest(".sidebar")?.getBoundingClientRect().right ??
      rect.right;
    setNotice(
      iconOnly
        ? { left: edge + 8, bottom: window.innerHeight - rect.bottom }
        : {
            left: rect.left,
            width: rect.width,
            bottom: window.innerHeight - rect.top + 8,
          },
    );
  }
  return (
    <>
      <button
        ref={button}
        type="button"
        className="nav-item sign-in"
        title={title}
        aria-label="Sign in with your organization"
        aria-expanded={!!notice}
        aria-controls="sidebar-sso-notice"
        onClick={toggle}
      >
        <LogIn size={16} aria-hidden="true" />
        <span className="nav-text">Sign in</span>
      </button>
      {notice && (
        <div
          ref={panel}
          id="sidebar-sso-notice"
          className="sidebar-notice"
          role="status"
          style={notice}
        >
          <p>{ssoUnconfigured}</p>
          <button
            type="button"
            className="sidebar-notice-close"
            aria-label="Dismiss"
            onClick={() => {
              setNotice(null);
              button.current?.focus();
            }}
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}
    </>
  );
}

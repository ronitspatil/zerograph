import { useId } from "react";
import { cn } from "@/lib/utils";
/**
 * ZeroGraph mark: a shield with a zero cut out of it, shaded with a subtle
 * top-to-bottom teal gradient. Mirrors
 * public/favicon.svg, which adds a dark tile for light browser chrome.
 */
export function LogoMark({
  size = 24,
  className,
}: {
  size?: number;
  className?: string;
}) {
  // Per-instance gradient id so several marks on one page never collide.
  const gradient = `zg-logo-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  return (
    <svg
      className={cn("logo-mark", className)}
      width={size}
      height={size}
      viewBox="3 3 18 18"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient
          id={gradient}
          x1="0"
          y1="3.8"
          x2="0"
          y2="20.2"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="#8fdcc6" />
          <stop offset="1" stopColor="#3fae8c" />
        </linearGradient>
      </defs>
      <path
        fillRule="evenodd"
        fill={`url(#${gradient})`}
        d="M12 3.8L19 6.4V11.8C19 15.9 16.1 18.9 12 20.2C7.9 18.9 5 15.9 5 11.8V6.4ZM12 8.4A2.7 3.5 0 1 0 12 15.4A2.7 3.5 0 1 0 12 8.4Z"
      />
    </svg>
  );
}
export function Wordmark({
  className,
  size,
}: {
  className?: string;
  size?: number;
}) {
  return (
    <span className={cn("wordmark", className)}>
      <LogoMark size={size} />
      <span className="wordmark-text">ZeroGraph</span>
    </span>
  );
}

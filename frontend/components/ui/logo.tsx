import { cn } from "@/lib/utils";
/**
 * ZeroGraph mark: a ring (the zero) around a hub node, joined by one edge to a
 * brighter node on the ring. Mirrors public/favicon.svg, which adds a dark tile.
 */
export function LogoMark({
  size = 24,
  className,
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      className={cn("logo-mark", className)}
      width={size}
      height={size}
      viewBox="2 2 20 20"
      aria-hidden="true"
      focusable="false"
    >
      <circle
        cx="12"
        cy="12"
        r="6.5"
        fill="none"
        stroke="var(--logo-edge, #3f9a87)"
        strokeWidth="1.6"
      />
      <path
        d="M12 12L16.6 7.4"
        stroke="var(--logo-edge, #3f9a87)"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
      <circle cx="12" cy="12" r="2.1" fill="var(--logo-node, #6cc7b3)" />
      <circle
        cx="16.6"
        cy="7.4"
        r="2.6"
        fill="var(--logo-hub, #b4f5e1)"
        stroke="var(--logo-gap, var(--surface, #0f1621))"
        strokeWidth="1.2"
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

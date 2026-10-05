import { cn } from "@/lib/utils";
/**
 * ZeroGraph mark: four nodes joined into a "Z" by three edges, with a brighter
 * hub node where the diagonal crosses the centre. Mirrors public/favicon.svg.
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
      viewBox="0 0 24 24"
      aria-hidden="true"
      focusable="false"
    >
      <rect
        x="0.5"
        y="0.5"
        width="23"
        height="23"
        rx="5"
        fill="var(--logo-tile, #0c1715)"
        stroke="var(--logo-tile-edge, #1b302b)"
      />
      <path
        d="M6 6.5H18L6 17.5H18"
        fill="none"
        stroke="var(--logo-edge, #3f9a87)"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <g fill="var(--logo-node, #6cc7b3)">
        <circle cx="6" cy="6.5" r="2" />
        <circle cx="18" cy="6.5" r="2" />
        <circle cx="6" cy="17.5" r="2" />
        <circle cx="18" cy="17.5" r="2" />
      </g>
      <circle
        cx="12"
        cy="12"
        r="2.7"
        fill="var(--logo-hub, #b4f5e1)"
        stroke="var(--logo-tile, #0c1715)"
        strokeWidth="1"
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

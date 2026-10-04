import { cn } from "@/lib/utils";
/** ZeroGraph mark: a plain "Z" stroke in a rounded square. Mirrors public/favicon.svg. */
export function LogoMark({
  size = 20,
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
      viewBox="0 0 20 20"
      aria-hidden="true"
      focusable="false"
    >
      <rect width="20" height="20" rx="4.5" fill="currentColor" />
      <path
        d="M6.25 6.25h7.5l-7.5 7.5h7.5"
        fill="none"
        stroke="var(--logo-ink, #0b111b)"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("wordmark", className)}>
      <LogoMark />
      <span className="wordmark-text">ZeroGraph</span>
    </span>
  );
}

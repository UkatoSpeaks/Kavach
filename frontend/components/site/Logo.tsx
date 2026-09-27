import Link from "next/link";
import { cn } from "@/lib/cn";

/** The shield mark. The same drawing is in app/icon.svg. */
export function ShieldMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" className={cn("size-8 shrink-0", className)}>
      <path
        d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V7L16 2.5Z"
        fill="#4338CA"
        stroke="#111"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path
        d="m10.5 16 3.8 3.8 7.4-7.6"
        fill="none"
        stroke="#fff"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    <Link
      href="/"
      aria-label="Kavach home"
      className={cn("inline-flex items-center gap-2 rounded-lg", className)}
    >
      <ShieldMark />
      <span className="font-display text-2xl leading-none font-extrabold tracking-tight">
        Kavach
      </span>
    </Link>
  );
}

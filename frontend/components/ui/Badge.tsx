import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

const tones = {
  neutral: "bg-card text-ink",
  accent: "bg-accent-tint text-accent-dark",
  ink: "bg-ink text-paper",
  safe: "bg-safe-tint text-safe-deep",
  suspicious: "bg-suspicious-tint text-suspicious-deep",
  scam: "bg-scam-tint text-scam-deep",
};

type BadgeProps = {
  children: ReactNode;
  tone?: keyof typeof tones;
  icon?: ReactNode;
  className?: string;
};

/** Small bordered pill label. */
export function Badge({ children, tone = "neutral", icon, className }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border-2 border-ink px-3 py-1",
        "text-sm leading-none font-semibold tracking-wide",
        tones[tone],
        className,
      )}
    >
      {icon}
      {children}
    </span>
  );
}

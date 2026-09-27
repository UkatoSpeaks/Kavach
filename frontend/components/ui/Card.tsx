import type { ComponentPropsWithoutRef, ElementType } from "react";
import { cn } from "@/lib/cn";

type CardProps<T extends ElementType> = {
  as?: T;
  /** Background tone. Verdict tones are for verdicts only. */
  tone?: "white" | "paper" | "accent" | "safe" | "suspicious" | "scam";
} & ComponentPropsWithoutRef<T>;

const tones = {
  white: "bg-card",
  paper: "bg-paper",
  accent: "bg-accent-tint",
  safe: "bg-safe-tint",
  suspicious: "bg-suspicious-tint",
  scam: "bg-scam-tint",
};

/** White, 2px ink border, rounded-2xl, hard offset shadow. */
export function Card<T extends ElementType = "div">({
  as,
  tone = "white",
  className,
  ...props
}: CardProps<T>) {
  const Tag = as ?? "div";
  return (
    <Tag
      className={cn("rounded-2xl border-2 border-ink shadow-brutal", tones[tone], className)}
      {...props}
    />
  );
}

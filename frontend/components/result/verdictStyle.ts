import { ShieldAlert, ShieldCheck, ShieldQuestion, type LucideIcon } from "lucide-react";
import type { Verdict } from "@/lib/types";

/** Verdict colours (the only place they are used) and icons, per verdict. */
export const VERDICT_STYLE: Record<
  Verdict,
  { tint: string; deep: string; solid: string; color: string; Icon: LucideIcon }
> = {
  safe: {
    tint: "bg-safe-tint",
    deep: "text-safe-deep",
    solid: "bg-safe",
    color: "var(--color-safe)",
    Icon: ShieldCheck,
  },
  suspicious: {
    tint: "bg-suspicious-tint",
    deep: "text-suspicious-deep",
    solid: "bg-suspicious",
    color: "var(--color-suspicious)",
    Icon: ShieldQuestion,
  },
  scam: {
    tint: "bg-scam-tint",
    deep: "text-scam-deep",
    solid: "bg-scam",
    color: "var(--color-scam)",
    Icon: ShieldAlert,
  },
};

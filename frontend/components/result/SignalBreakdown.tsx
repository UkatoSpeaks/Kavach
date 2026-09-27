"use client";

import { motion } from "motion/react";
import { useId } from "react";
import { signalLabel, signalStatus, signalSummary, unavailableReason } from "@/lib/labels";
import type { RedFlag, Signal } from "@/lib/types";
import { usePrefersReducedMotion } from "@/lib/useReducedMotion";
import { cn } from "@/lib/cn";
import { SectionTitle } from "./SectionTitle";

type SignalBreakdownProps = {
  signals: Signal[];
  flags: RedFlag[];
};

/** "How we decided": each check's score and weight as a labelled bar. */
export function SignalBreakdown({ signals, flags }: SignalBreakdownProps) {
  const id = useId();
  const reduced = usePrefersReducedMotion();
  if (signals.length === 0) return null;

  return (
    <section aria-labelledby={`${id}-title`}>
      <SectionTitle id={`${id}-title`}>How we decided</SectionTitle>
      <p className="mt-1 text-sm text-ink-muted">
        The score combines these checks. Bars show each check&apos;s risk score out of 100.
      </p>
      <ul className="mt-4 flex flex-col gap-4">
        {signals.map((s) => {
          const status = signalStatus(s);
          const score = Math.round(s.score);
          const summary = status === "unavailable" ? unavailableReason(s) : signalSummary(s, flags);
          return (
            <li key={s.source} className={cn(status === "unavailable" && "text-ink-muted")}>
              <div className="flex flex-wrap items-baseline justify-between gap-x-3">
                <span className="font-bold">{signalLabel(s.source)}</span>
                <span className="text-sm font-semibold tabular-nums">
                  {status === "unavailable" ? (
                    "Not available"
                  ) : status === "counted" ? (
                    <>
                      {score}/100 <span className="text-ink-muted">· counts {Math.round(s.weight * 100)}%</span>
                    </>
                  ) : (
                    <>
                      {score}/100 <span className="text-ink-muted">· not counted</span>
                    </>
                  )}
                </span>
              </div>

              <div
                aria-hidden
                className={cn(
                  "mt-1.5 h-3.5 overflow-hidden rounded-full border-2",
                  status === "unavailable"
                    ? "border-dashed border-ink/40 bg-[repeating-linear-gradient(135deg,transparent_0_6px,rgb(17_17_17/0.08)_6px_12px)]"
                    : "border-ink bg-card",
                )}
              >
                {status !== "unavailable" && (
                  <motion.div
                    className={cn("h-full", status === "counted" ? "bg-accent" : "bg-ink/35")}
                    initial={reduced ? false : { width: 0 }}
                    animate={{ width: `${score}%` }}
                    transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1], delay: 0.2 }}
                  />
                )}
              </div>

              <p
                title={summary}
                className="mt-1 line-clamp-2 text-sm text-ink-muted [overflow-wrap:anywhere]"
              >
                {summary}
              </p>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

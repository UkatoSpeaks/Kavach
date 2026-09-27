"use client";

import { AnimatePresence, motion, useInView } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { AlertTriangle, ChevronLeft, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/cn";
import { usePrefersReducedMotion } from "@/lib/useReducedMotion";

/**
 * Hero demo: a fake SBI KYC SMS gets scanned, its red flags are highlighted one by one,
 * then a verdict badge slides in. Loops while on screen; static final state for reduced motion.
 */

type Segment = { text: string; flag?: number; url?: boolean };

// A made-up but typical smishing SMS. The domain is a lookalike ("sbl", not "sbi").
const MESSAGE: Segment[] = [
  { text: "Dear Customer, your SBI YONO account will be " },
  { text: "BLOCKED today", flag: 1 },
  { text: ". " },
  { text: "Update your PAN/KYC immediately", flag: 2 },
  { text: " by clicking " },
  { text: "http://sbl-kyc-update.top/verify", flag: 3, url: true },
  { text: " -SBI" },
];

const FLAGS = [
  { step: 1, label: "Threat: account blocked" },
  { step: 2, label: "Urgent KYC request by SMS" },
  { step: 3, label: "Lookalike link: sbl ≠ sbi" },
];

// Steps: 0 idle, 1 scanning, 2-4 highlight flags 1-3, 5 verdict shown.
const FINAL = 5;
const DURATIONS = [900, 1700, 700, 700, 800, 3800];
const flagVisible = (flag: number, step: number) => step >= flag + 1;

export function DemoCard() {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { amount: 0.4 });
  const reduced = usePrefersReducedMotion();
  const [step, setStep] = useState(0);
  const shown = reduced ? FINAL : step;

  useEffect(() => {
    if (reduced || !inView) return;
    const t = setTimeout(() => setStep((s) => (s + 1) % DURATIONS.length), DURATIONS[step]);
    return () => clearTimeout(t);
  }, [step, inView, reduced]);

  return (
    <figure ref={ref} className="relative mx-auto w-full max-w-md">
      <figcaption className="sr-only">
        Example: a fake SBI KYC text message. Kavach highlights three red flags — a threat that
        the account will be blocked, an urgent KYC request, and a lookalike link — and marks it
        as a scam, 93 out of 100.
      </figcaption>

      <div
        aria-hidden="true"
        className="overflow-hidden rounded-[2rem] border-2 border-ink bg-card shadow-brutal-lg lg:rotate-1"
      >
        {/* Phone header */}
        <div className="flex items-center gap-3 border-b-2 border-ink bg-paper px-4 py-3">
          <ChevronLeft className="size-5 shrink-0" />
          <div className="flex size-10 shrink-0 items-center justify-center rounded-full border-2 border-ink bg-accent-tint font-bold text-accent-dark">
            98
          </div>
          <div className="min-w-0">
            <p className="truncate leading-tight font-bold">+91 98XXX X4521</p>
            <p className="text-sm leading-tight text-ink-muted">Text message · Today 10:42</p>
          </div>
        </div>

        {/* SMS bubble */}
        <div className="px-4 pt-5 pb-4">
          <div className="relative max-w-[92%] overflow-hidden rounded-2xl rounded-tl-sm border-2 border-ink bg-[#F1F0EC] px-4 py-3">
            <p className="text-base leading-relaxed">
              {MESSAGE.map((seg, i) =>
                seg.flag ? (
                  <mark
                    key={i}
                    className={cn(
                      "rounded bg-transparent bg-no-repeat px-0.5 text-inherit transition-[background-size,box-shadow] duration-500 ease-out",
                      "bg-[linear-gradient(var(--color-scam-tint),var(--color-scam-tint))]",
                      seg.url && "break-all text-accent-dark underline",
                      flagVisible(seg.flag, shown)
                        ? "bg-size-[100%_100%] shadow-[inset_0_-3px_0_var(--color-scam)]"
                        : "bg-size-[0%_100%]",
                    )}
                  >
                    {seg.text}
                  </mark>
                ) : (
                  <span key={i}>{seg.text}</span>
                ),
              )}
            </p>

            <AnimatePresence>
              {shown === 1 && (
                <motion.div
                  key="scan"
                  className="pointer-events-none absolute inset-x-0 h-10 -translate-y-full bg-linear-to-b from-transparent to-accent/25"
                  initial={{ top: "0%", opacity: 0 }}
                  animate={{ top: "115%", opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 1.5, ease: "easeInOut" }}
                >
                  <div className="absolute inset-x-0 bottom-0 h-0.5 bg-accent" />
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* Kavach result */}
        <div className="border-t-2 border-dashed border-ink/30 px-4 pt-3 pb-5">
          <div className="flex min-h-11 items-center justify-between gap-3">
            <p className="flex items-center gap-2 text-sm font-bold">
              <span
                className={cn(
                  "size-2.5 rounded-full",
                  shown === 1 ? "animate-pulse bg-accent" : shown >= 2 ? "bg-scam" : "bg-ink/30",
                )}
              />
              {shown === 0 ? "Kavach ready" : shown === 1 ? "Scanning…" : "Kavach check"}
            </p>
            <AnimatePresence>
              {shown === FINAL && (
                <motion.span
                  key="verdict"
                  initial={reduced ? false : { x: 40, opacity: 0 }}
                  animate={{ x: 0, opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ type: "spring", stiffness: 380, damping: 22 }}
                  className="inline-flex items-center gap-1.5 rounded-full border-2 border-ink bg-scam px-3 py-1.5 font-display font-extrabold tracking-wide whitespace-nowrap text-white shadow-brutal-sm"
                >
                  <ShieldAlert className="size-4" />
                  SCAM · 93/100
                </motion.span>
              )}
            </AnimatePresence>
          </div>

          <ul className="mt-3 flex flex-col gap-2">
            {FLAGS.map((f) => (
              <li
                key={f.step}
                className={cn(
                  "flex items-center gap-2 text-sm font-semibold text-scam-deep transition-[opacity,transform] duration-300",
                  flagVisible(f.step, shown) ? "opacity-100" : "translate-x-2 opacity-0",
                )}
              >
                <AlertTriangle className="size-4 shrink-0" />
                {f.label}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </figure>
  );
}

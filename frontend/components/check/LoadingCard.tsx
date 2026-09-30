"use client";

import { useEffect, useState } from "react";
import { Coffee, Loader2 } from "lucide-react";
import { Card } from "@/components/ui/Card";

const STEPS = [
  "Reading the message…",
  "Checking links and UPI IDs…",
  "Looking up community reports…",
  "Writing the explanation…",
];

/** Reading the image takes a few seconds on its own. */
const SCREENSHOT_STEPS = [
  "Reading your screenshot…",
  "Checking the sender…",
  ...STEPS.slice(1),
];

type LoadingCardProps = {
  /** True once the request has taken long enough that the server is probably waking up. */
  slow: boolean;
  /** A screenshot is being read first. */
  screenshot?: boolean;
};

/** Shown in the result column while a check runs. */
export function LoadingCard({ slow, screenshot = false }: LoadingCardProps) {
  const steps = screenshot ? SCREENSHOT_STEPS : STEPS;
  const [step, setStep] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setStep((s) => Math.min(s + 1, steps.length - 1)), screenshot ? 2200 : 1400);
    return () => clearInterval(t);
  }, [steps.length, screenshot]);

  return (
    <Card className="p-5 sm:p-6">
      <p className="flex items-center gap-3 font-display text-2xl font-extrabold">
        <Loader2 aria-hidden className="size-6 animate-spin text-accent" />
        {screenshot && step === 0 ? "Reading your screenshot…" : "Checking…"}
      </p>
      <ol className="mt-4 flex flex-col gap-2" aria-hidden>
        {steps.map((label, i) => (
          <li
            key={label}
            className={i <= step ? "font-semibold text-ink" : "text-ink-muted/60"}
          >
            {label}
          </li>
        ))}
      </ol>

      {slow && (
        <p className="mt-5 flex gap-3 rounded-xl border-2 border-ink bg-accent-tint p-3 text-sm">
          <Coffee aria-hidden className="mt-0.5 size-5 shrink-0 text-accent-dark" />
          <span>
            <strong>Waking up the server</strong> — the free server sleeps when idle, this can take
            up to a minute.
          </span>
        </p>
      )}

    </Card>
  );
}

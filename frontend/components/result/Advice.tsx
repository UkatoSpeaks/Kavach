import { useId } from "react";
import { CheckCircle2, ExternalLink, PhoneCall } from "lucide-react";
import type { Verdict } from "@/lib/types";
import { SectionTitle } from "./SectionTitle";

const REPORT_LINE = /1930|cybercrime\.gov\.in/i;

type AdviceProps = {
  advice: string[];
  verdict: Verdict;
};

/**
 * "What to do" as a checklist. For warnings, the report line (1930 / cybercrime.gov.in)
 * becomes an emergency box instead.
 */
export function Advice({ advice, verdict }: AdviceProps) {
  const id = useId();
  const warning = verdict !== "safe";
  const steps = warning ? advice.filter((a) => !REPORT_LINE.test(a)) : advice;

  if (steps.length === 0 && !warning) return null;

  return (
    <section aria-labelledby={`${id}-title`}>
      <SectionTitle id={`${id}-title`}>What to do</SectionTitle>
      {steps.length > 0 && (
        <ul className="mt-3 flex flex-col gap-2.5">
          {steps.map((step) => (
            <li key={step} className="flex gap-3">
              <CheckCircle2 aria-hidden className="mt-1 size-5 shrink-0 text-accent" />
              <span className="text-pretty">{step}</span>
            </li>
          ))}
        </ul>
      )}

      {warning && (
        <div className="mt-4 rounded-xl border-2 border-ink bg-ink p-4 text-paper shadow-brutal-sm">
          <p className="flex items-center gap-2 font-display text-lg font-extrabold">
            <PhoneCall aria-hidden className="size-5 shrink-0" />
            Already paid or shared details?
          </p>
          <p className="mt-1 text-paper/90">
            Act fast — the sooner you report, the better the chance of stopping the money.
          </p>
          <div className="mt-3 flex flex-col gap-2 sm:flex-row">
            <a
              href="tel:1930"
              className="inline-flex min-h-12 items-center justify-center gap-2 rounded-xl border-2 border-paper bg-paper px-4 font-bold text-ink hover:bg-accent-tint"
            >
              <PhoneCall aria-hidden className="size-4" />
              Call 1930
              <span className="sr-only">(national cyber crime helpline)</span>
            </a>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex min-h-12 items-center justify-center gap-2 rounded-xl border-2 border-paper px-4 font-bold text-paper hover:bg-paper/10"
            >
              Report at cybercrime.gov.in
              <ExternalLink aria-hidden className="size-4" />
              <span className="sr-only">(opens in a new tab)</span>
            </a>
          </div>
        </div>
      )}
    </section>
  );
}

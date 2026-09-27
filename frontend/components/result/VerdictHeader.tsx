import type { Ref } from "react";
import { Info } from "lucide-react";
import { VERDICT_LABEL, VERDICT_SUMMARY, scamTypeLabel } from "@/lib/labels";
import type { AnalysisResult } from "@/lib/types";
import { cn } from "@/lib/cn";
import { ScoreGauge } from "./ScoreGauge";
import { VERDICT_STYLE } from "./verdictStyle";

type VerdictHeaderProps = {
  result: AnalysisResult;
  /** The heading receives focus when a new result appears. */
  headingRef?: Ref<HTMLHeadingElement>;
};

export function VerdictHeader({ result, headingRef }: VerdictHeaderProps) {
  const style = VERDICT_STYLE[result.verdict];
  const type = scamTypeLabel(result.scam_type);

  return (
    <div className={cn("rounded-t-2xl border-b-2 border-ink p-5 sm:p-6", style.tint)}>
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-4">
        <div className="min-w-0 flex-1 basis-52">
          <h2
            ref={headingRef}
            tabIndex={-1}
            className={cn(
              "flex items-center gap-3 font-display text-5xl leading-none font-extrabold tracking-tight sm:text-6xl",
              style.deep,
            )}
          >
            <span
              className={cn(
                "flex size-12 shrink-0 items-center justify-center rounded-xl border-2 border-ink text-white shadow-brutal-sm sm:size-14",
                style.solid,
              )}
            >
              <style.Icon aria-hidden className="size-7 sm:size-8" />
            </span>
            <span>
              <span className="sr-only">Result: </span>
              {VERDICT_LABEL[result.verdict]}
            </span>
          </h2>
          <p className="mt-3 text-lg font-bold">{VERDICT_SUMMARY[result.verdict]}</p>
          {type && (
            <p className="mt-1 text-ink-muted">
              <span className="font-semibold text-ink">Type:</span> {type}
            </p>
          )}
        </div>
        <ScoreGauge
          score={result.risk_score}
          color={style.color}
          className="w-40 shrink-0 sm:w-48"
        />
      </div>

      {result.confidence === "low" && (
        <p className="mt-4 flex gap-2 rounded-xl border-2 border-ink bg-card px-3 py-2 text-sm">
          <Info aria-hidden className="mt-0.5 size-4 shrink-0 text-accent" />
          <span>
            Low confidence: our AI review strongly disagreed with the other checks, so it was left
            out. Treat this result with extra care.
          </span>
        </p>
      )}
    </div>
  );
}

"use client";

import { MotionConfig, motion } from "motion/react";
import type { Ref } from "react";
import { OCR_ENGINE_LABEL } from "@/lib/labels";
import { isScreenshotResult, type AnalysisResult } from "@/lib/types";
import { useExplanationLang } from "@/lib/useExplanationLang";
import { Card } from "@/components/ui/Card";
import { Advice } from "./Advice";
import { CheckedInput, type CheckedSource } from "./CheckedInput";
import { Explanation } from "./Explanation";
import { RecheckText } from "./RecheckText";
import { ResultActions } from "./ResultActions";
import { SignalBreakdown } from "./SignalBreakdown";
import { SimilarPatterns } from "./SimilarPatterns";
import { VerdictHeader } from "./VerdictHeader";

type ResultPanelProps = {
  result: AnalysisResult;
  source: CheckedSource;
  headingRef?: Ref<HTMLHeadingElement>;
  /** Shown as "Check another"; omitted on shared (read-only) results. */
  onCheckAnother?: () => void;
  readOnly?: boolean;
  /** Screenshots: check the (corrected) text read from the image as a message. */
  onRecheckText?: (text: string) => void;
};

/** The full verdict: header, highlighted input, explanation, advice, breakdown, actions. */
export function ResultPanel({
  result,
  source,
  headingRef,
  onCheckAnother,
  readOnly = false,
  onRecheckText,
}: ResultPanelProps) {
  const [lang, setLang] = useExplanationLang();
  const ocrNote = isScreenshotResult(result)
    ? `Screenshot text read by ${OCR_ENGINE_LABEL[result.ocr_engine]}. The image was not stored.`
    : undefined;

  return (
    <MotionConfig reducedMotion="user">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, ease: "easeOut" }}
      >
        <Card className="overflow-hidden">
          <VerdictHeader result={result} headingRef={headingRef} />
          <div className="flex flex-col gap-8 p-5 sm:p-6">
            <CheckedInput source={source} flags={result.red_flags} lang={lang} />
            {source.kind === "screenshot" && onRecheckText && !readOnly && (
              <RecheckText text={source.text} onRecheck={onRecheckText} />
            )}
            <Explanation
              en={result.explanation_en}
              hi={result.explanation_hi}
              lang={lang}
              onLangChange={setLang}
            />
            <Advice advice={result.advice} verdict={result.verdict} />
            <SignalBreakdown
              signals={result.signal_breakdown}
              flags={result.red_flags}
              note={ocrNote}
            />
            <SimilarPatterns patterns={result.similar_patterns} />
            <div className="border-t-2 border-dashed border-ink/30 pt-6">
              <ResultActions
                result={result}
                onCheckAnother={onCheckAnother}
                canReport={!readOnly}
              />
              <p className="mt-5 text-sm text-ink-muted">
                Kavach can be wrong. When in doubt, don&apos;t pay — call your bank on the number
                printed on your card.
              </p>
            </div>
          </div>
        </Card>
      </motion.div>
    </MotionConfig>
  );
}

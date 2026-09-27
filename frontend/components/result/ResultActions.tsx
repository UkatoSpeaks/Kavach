"use client";

import { useState } from "react";
import { Flag, RotateCcw, Share2 } from "lucide-react";
import { VERDICT_LABEL, scamTypeLabel } from "@/lib/labels";
import type { AnalysisResult } from "@/lib/types";
import { Button } from "@/components/ui/Button";
import { ReportPanel } from "./ReportPanel";

type ResultActionsProps = {
  result: AnalysisResult;
  /** Omit on shared results, which are read-only. */
  onCheckAnother?: () => void;
  canReport?: boolean;
};

/** Short WhatsApp message with a link to the result. */
function shareText(result: AnalysisResult): string {
  const url = result.id ? `${window.location.origin}/r/${result.id}` : window.location.origin;
  if (result.verdict === "safe") {
    return `I checked a message with Kavach: it looks safe (${result.risk_score}/100 risk). Check yours before you pay: ${url}`;
  }
  const type = result.scam_type ? scamTypeLabel(result.scam_type)?.split(" — ")[0] : null;
  return [
    `⚠️ Scam alert: Kavach rated a message ${VERDICT_LABEL[result.verdict]} (${result.risk_score}/100)${type ? ` — ${type}` : ""}.`,
    "If you get it too, don't click links, don't pay and never share your UPI PIN or OTP.",
    `Why: ${url}`,
  ].join("\n");
}

export function ResultActions({ result, onCheckAnother, canReport = true }: ResultActionsProps) {
  const [reporting, setReporting] = useState(false);
  const reportable =
    canReport && result.verdict !== "safe" && result.id !== null && (result.entities?.length ?? 0) > 0;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">
        {reportable && (
          <Button
            variant="secondary"
            aria-expanded={reporting}
            onClick={() => setReporting((r) => !r)}
            icon={<Flag aria-hidden className="order-first size-5" />}
          >
            Report this
          </Button>
        )}
        <Button
          variant="secondary"
          onClick={() => {
            const href = `https://wa.me/?text=${encodeURIComponent(shareText(result))}`;
            window.open(href, "_blank", "noopener,noreferrer");
          }}
          icon={<Share2 aria-hidden className="order-first size-5" />}
        >
          {result.verdict === "safe" ? "Share result" : "Share warning"}
          <span className="sr-only">on WhatsApp (opens in a new tab)</span>
        </Button>
        {onCheckAnother && (
          <Button
            onClick={onCheckAnother}
            icon={<RotateCcw aria-hidden className="order-first size-5" />}
          >
            Check another
          </Button>
        )}
      </div>
      {reporting && reportable && <ReportPanel result={result} />}
    </div>
  );
}

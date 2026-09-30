"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { analyzeQr, analyzeScreenshot, analyzeText, analyzeUpi, analyzeUrl } from "@/lib/api";
import { friendlyError, type FriendlyError } from "@/lib/errors";
import type { Example } from "@/lib/examples";
import { VERDICT_LABEL } from "@/lib/labels";
import { isScreenshotResult, type AnalysisResult } from "@/lib/types";
import { ResultPanel } from "@/components/result/ResultPanel";
import type { CheckedSource } from "@/components/result/CheckedInput";
import { EmptyState } from "./EmptyState";
import { ErrorNotice } from "./ErrorNotice";
import { InputPanel, isImageTab, type ImageTab, type InputValues, type Tab } from "./InputPanel";
import { LoadingCard } from "./LoadingCard";

/** After this long, the free server is probably waking up: say so. */
const SLOW_AFTER_MS = 6000;

type Submission =
  | { kind: "text"; text: string }
  | { kind: "url"; url: string }
  | { kind: "upi"; value: string }
  | { kind: "qr" | "screenshot"; file: File; previewUrl: string };

type Phase =
  | { state: "idle" }
  | { state: "loading"; slow: boolean; screenshot: boolean }
  | { state: "done"; result: AnalysisResult; source: CheckedSource }
  | { state: "error"; error: FriendlyError; attempt: number; retry: Submission };

function call(sub: Submission, signal: AbortSignal): Promise<AnalysisResult> {
  switch (sub.kind) {
    case "text":
      return analyzeText({ text: sub.text }, { signal });
    case "url":
      return analyzeUrl({ url: sub.url.trim() }, { signal });
    case "upi": {
      const v = sub.value.trim();
      return analyzeUpi(/^upi:\/\//i.test(v) ? { upi_uri: v } : { upi_id: v }, { signal });
    }
    case "qr":
      return analyzeQr(sub.file, { signal });
    case "screenshot":
      return analyzeScreenshot(sub.file, { signal });
  }
}

function sourceOf(sub: Submission, result: AnalysisResult): CheckedSource {
  switch (sub.kind) {
    case "text":
      return { kind: "text", text: sub.text };
    case "url":
      return { kind: "url", text: sub.url.trim() };
    case "upi":
      return { kind: "upi", text: sub.value.trim() };
    case "qr":
      return { kind: "qr", imageUrl: sub.previewUrl };
    case "screenshot":
      return isScreenshotResult(result)
        ? {
            kind: "screenshot",
            imageUrl: sub.previewUrl,
            text: result.extracted_text,
            sender: result.sender,
            app: result.app,
            isPaymentReceipt: result.is_payment_receipt,
          }
        : { kind: "qr", imageUrl: sub.previewUrl };
  }
}

const EMPTY_FIELD = {
  qr: { qrFile: null, qrPreview: null },
  screenshot: { shotFile: null, shotPreview: null },
} as const;

/** The /check page: input panel, then empty state, loading, error or result. */
export function Checker() {
  const [tab, setTab] = useState<Tab>("text");
  const [values, setValues] = useState<InputValues>({
    text: "",
    url: "",
    upi: "",
    qrFile: null,
    qrPreview: null,
    shotFile: null,
    shotPreview: null,
  });
  const [phase, setPhase] = useState<Phase>({ state: "idle" });
  const [announcement, setAnnouncement] = useState("");

  const controller = useRef<AbortController | null>(null);
  const attempts = useRef(0);
  const fieldRef = useRef<HTMLTextAreaElement | HTMLInputElement | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const previews = useRef<Set<string>>(new Set());

  // Object URLs for image previews live until the page unmounts (a result may still show one).
  useEffect(() => {
    const urls = previews.current;
    return () => {
      controller.current?.abort();
      urls.forEach((u) => URL.revokeObjectURL(u));
    };
  }, []);

  const run = useCallback(async (sub: Submission) => {
    controller.current?.abort();
    const ctrl = new AbortController();
    controller.current = ctrl;
    const screenshot = sub.kind === "screenshot";
    setPhase({ state: "loading", slow: false, screenshot });
    setAnnouncement(screenshot ? "Reading your screenshot…" : "Checking…");
    const slowTimer = setTimeout(() => {
      setPhase((p) => (p.state === "loading" ? { ...p, slow: true } : p));
      setAnnouncement("Waking up the server. This can take up to a minute.");
    }, SLOW_AFTER_MS);
    ctrl.signal.addEventListener("abort", () => clearTimeout(slowTimer));

    try {
      const result = await call(sub, ctrl.signal);
      if (ctrl.signal.aborted) return;
      setPhase({ state: "done", result, source: sourceOf(sub, result) });
      setAnnouncement(
        `Result: ${VERDICT_LABEL[result.verdict]}, risk score ${result.risk_score} out of 100.`,
      );
    } catch (err) {
      if (ctrl.signal.aborted) return; // cancelled or superseded; the UI already moved on
      const error = friendlyError(err, sub.kind);
      attempts.current += 1;
      setPhase({ state: "error", error, attempt: attempts.current, retry: sub });
      setAnnouncement(error.title);
    } finally {
      clearTimeout(slowTimer);
    }
  }, []);

  // Move focus to the verdict when a result appears (also scrolls it into view on phones).
  useEffect(() => {
    if (phase.state === "done") headingRef.current?.focus();
    if (phase.state === "error") resultRef.current?.scrollIntoView({ block: "nearest" });
  }, [phase]);

  function submission(t: Tab, v: InputValues): Submission | null {
    switch (t) {
      case "text":
        return v.text.trim() ? { kind: "text", text: v.text } : null;
      case "url":
        return v.url.trim() ? { kind: "url", url: v.url } : null;
      case "upi":
        return v.upi.trim() ? { kind: "upi", value: v.upi } : null;
      case "qr":
        return v.qrFile && v.qrPreview
          ? { kind: "qr", file: v.qrFile, previewUrl: v.qrPreview }
          : null;
      case "screenshot":
        return v.shotFile && v.shotPreview
          ? { kind: "screenshot", file: v.shotFile, previewUrl: v.shotPreview }
          : null;
    }
  }

  function setImageFile(t: ImageTab, file: File | null): InputValues {
    let preview: string | null = null;
    if (file) {
      preview = URL.createObjectURL(file);
      previews.current.add(preview);
    }
    const next =
      t === "qr"
        ? { ...values, qrFile: file, qrPreview: preview }
        : { ...values, shotFile: file, shotPreview: preview };
    setValues(next);
    return next;
  }

  async function pickExample(t: Tab, ex: Example) {
    setTab(t);
    let next: InputValues;
    if (isImageTab(t)) {
      try {
        const blob = await (await fetch(ex.value)).blob();
        const name = ex.value.split("/").pop() ?? "example.png";
        next = setImageFile(t, new File([blob], name, { type: blob.type || "image/png" }));
      } catch {
        return;
      }
    } else {
      next = { ...values, [t]: ex.value };
      setValues(next);
    }
    const sub = submission(t, next);
    if (sub) void run(sub);
  }

  function cancel() {
    controller.current?.abort();
    setPhase({ state: "idle" });
    setAnnouncement("Check cancelled.");
  }

  /** Check the (corrected) text read from a screenshot, as a message. */
  function recheckText(text: string) {
    setTab("text");
    setValues((v) => ({ ...v, text }));
    void run({ kind: "text", text });
  }

  function switchToMessageTab() {
    setPhase({ state: "idle" });
    setTab("text");
    setAnnouncement("Switched to the Message tab. Paste the message text there.");
    requestAnimationFrame(() => {
      fieldRef.current?.focus();
      fieldRef.current?.scrollIntoView({ block: "center" });
    });
  }

  function checkAnother() {
    controller.current?.abort();
    setPhase({ state: "idle" });
    setValues((v) => ({ ...v, ...(isImageTab(tab) ? EMPTY_FIELD[tab] : { [tab]: "" }) }));
    setAnnouncement("");
    requestAnimationFrame(() => {
      fieldRef.current?.focus();
      fieldRef.current?.scrollIntoView({ block: "center" });
    });
  }

  const loading = phase.state === "loading";

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:items-start">
      <div className="lg:sticky lg:top-28">
        <InputPanel
          tab={tab}
          onTabChange={setTab}
          values={values}
          onValueChange={(t, v) => setValues((cur) => ({ ...cur, [t]: v }))}
          onImageChange={setImageFile}
          onSubmit={() => {
            const sub = submission(tab, values);
            if (sub) void run(sub);
          }}
          onCancel={cancel}
          onExample={pickExample}
          loading={loading}
          fieldRef={fieldRef}
        />
      </div>

      <div ref={resultRef} className="scroll-mt-28">
        <p aria-live="polite" role="status" className="sr-only">
          {announcement}
        </p>
        {phase.state === "idle" && <EmptyState onPick={(ex) => pickExample("text", ex)} />}
        {phase.state === "loading" && (
          <LoadingCard slow={phase.slow} screenshot={phase.screenshot} />
        )}
        {phase.state === "error" && (
          <ErrorNotice
            key={phase.attempt}
            error={phase.error}
            onRetry={() => run(phase.retry)}
            onUseMessageTab={phase.error.suggestMessageTab ? switchToMessageTab : undefined}
          />
        )}
        {phase.state === "done" && (
          <ResultPanel
            key={phase.result.id ?? phase.result.created_at}
            result={phase.result}
            source={phase.source}
            headingRef={headingRef}
            onCheckAnother={checkAnother}
            onRecheckText={recheckText}
          />
        )}
      </div>
    </div>
  );
}

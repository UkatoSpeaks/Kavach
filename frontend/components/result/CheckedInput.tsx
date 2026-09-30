"use client";

import { useId, useMemo, useState, type KeyboardEvent } from "react";
import { AlertTriangle, AppWindow, MousePointerClick, ReceiptIndianRupee, UserRound } from "lucide-react";
import { highlightEvidence } from "@/lib/highlight";
import type { Lang } from "@/lib/useExplanationLang";
import { SCREENSHOT_APP_LABEL } from "@/lib/labels";
import type { RedFlag, ScreenshotApp } from "@/lib/types";
import { cn } from "@/lib/cn";
import { SectionTitle } from "./SectionTitle";

/** What the user checked, as shown in the result. */
export type CheckedSource =
  | { kind: "text" | "url" | "upi"; text: string }
  | { kind: "qr"; imageUrl: string }
  /** `text` is what OCR read from the image: the evidence is highlighted in it. */
  | {
      kind: "screenshot";
      imageUrl: string;
      text: string;
      sender: string | null;
      app: ScreenshotApp | null;
      isPaymentReceipt: boolean;
    }
  /** A shared result: the original input isn't available. */
  | { kind: "none" };

const TITLES = {
  text: "Your message",
  url: "Your link",
  upi: "Your UPI ID",
  qr: "Your QR code",
  screenshot: "Your screenshot",
  none: "Warning signs",
};

type CheckedInputProps = {
  source: CheckedSource;
  flags: RedFlag[];
  lang: Lang;
};

function flagText(flag: RedFlag, lang: Lang): string {
  return lang === "hi" && flag.message_hi ? flag.message_hi : flag.message;
}

/**
 * The checked text with each red flag's evidence highlighted in place. Hover, focus or tap a
 * highlight to see why; evidence that can't be located is listed underneath.
 */
export function CheckedInput({ source, flags, lang }: CheckedInputProps) {
  const text =
    source.kind === "text" || source.kind === "url" || source.kind === "upi"
      ? source.text
      : source.kind === "screenshot" && source.text.trim()
        ? source.text
        : null;
  const { segments, unlocated } = useMemo(
    () =>
      text !== null
        ? highlightEvidence(text, flags)
        : { segments: [], unlocated: flags.map((_, i) => i) },
    [text, flags],
  );
  const [active, setActive] = useState<number[] | null>(null);
  const infoId = useId();
  const located = flags.length - unlocated.length;

  if (source.kind === "none" && flags.length === 0) return null;

  const toggle = (ids: number[]) =>
    setActive((cur) => (cur && cur.join() === ids.join() ? null : ids));
  const onKey = (e: KeyboardEvent, ids: number[]) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle(ids);
    }
  };

  return (
    <section aria-labelledby={`${infoId}-title`}>
      <SectionTitle id={`${infoId}-title`}>{TITLES[source.kind]}</SectionTitle>

      {source.kind === "qr" && (
        // eslint-disable-next-line @next/next/no-img-element -- a local blob: URL
        <img
          src={source.imageUrl}
          alt="The QR code you checked"
          className="mt-3 size-36 rounded-xl border-2 border-ink bg-card object-contain p-1"
        />
      )}

      {source.kind === "screenshot" && (
        <div className="mt-3 flex items-start gap-4">
          {/* eslint-disable-next-line @next/next/no-img-element -- a local blob: URL */}
          <img
            src={source.imageUrl}
            alt="The screenshot you checked"
            className="h-36 w-20 shrink-0 rounded-xl border-2 border-ink bg-card object-cover object-top"
          />
          <ScreenshotChips source={source} />
        </div>
      )}

      {text !== null && (
        <>
          <p
            className={cn(
              "mt-3 rounded-xl border-2 border-ink bg-paper px-4 py-3 whitespace-pre-wrap [overflow-wrap:anywhere]",
              (source.kind === "url" || source.kind === "upi") && "font-mono text-sm",
            )}
          >
            {segments.map((seg, i) =>
              seg.flags.length === 0 ? (
                <span key={i}>{seg.text}</span>
              ) : (
                <mark
                  key={i}
                  role="button"
                  tabIndex={0}
                  aria-pressed={active?.join() === seg.flags.join()}
                  onMouseEnter={() => setActive(seg.flags)}
                  onFocus={() => setActive(seg.flags)}
                  onClick={() => setActive(seg.flags)}
                  onKeyDown={(e) => onKey(e, seg.flags)}
                  className={cn(
                    "cursor-help bg-scam-tint text-inherit",
                    "shadow-[inset_0_-3px_0_var(--color-scam)] transition-colors hover:bg-scam/25",
                    active?.some((f) => seg.flags.includes(f)) && "bg-scam/25",
                  )}
                >
                  {seg.text}
                  <span className="sr-only">
                    {" "}
                    (warning: {seg.flags.map((f) => flags[f].message).join("; ")})
                  </span>
                </mark>
              ),
            )}
          </p>

          {located > 0 && (
            <div
              id={infoId}
              aria-hidden
              className="mt-2 min-h-12 rounded-xl border-2 border-dashed border-ink/40 px-3 py-2 text-sm"
            >
              {active ? (
                <ul className="flex flex-col gap-1">
                  {active.map((f) => (
                    <li key={f} className="flex gap-2 font-semibold text-scam-deep">
                      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                      <span lang={lang}>{flagText(flags[f], lang)}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="flex items-center gap-2 text-ink-muted">
                  <MousePointerClick className="size-4 shrink-0" />
                  Tap or hover a highlighted part to see why it&apos;s a warning sign.
                </p>
              )}
            </div>
          )}
        </>
      )}

      {unlocated.length > 0 && (
        <div className="mt-4">
          {text !== null && located > 0 && (
            <p className="text-sm font-bold text-ink-muted">Also found:</p>
          )}
          <ul className="mt-2 flex flex-col gap-2">
            {unlocated.map((i) => (
              <li key={i} className="flex gap-2">
                <AlertTriangle aria-hidden className="mt-1 size-4 shrink-0 text-scam" />
                <span>
                  <span lang={lang} className="font-semibold">
                    {flagText(flags[i], lang)}
                  </span>
                  {flags[i].evidence && (
                    <span className="mt-0.5 block font-mono text-sm text-ink-muted [overflow-wrap:anywhere]">
                      {flags[i].evidence}
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {source.kind === "screenshot" && text === null && (
        <p className="mt-3 text-sm text-ink-muted">No message text in the screenshot.</p>
      )}

      {flags.length === 0 && text !== null && (
        <p className="mt-2 text-sm text-ink-muted">No warning signs found in the text.</p>
      )}
    </section>
  );
}

type ScreenshotSource = Extract<CheckedSource, { kind: "screenshot" }>;

const chipClass =
  "inline-flex max-w-full items-center gap-1.5 rounded-full border-2 border-ink bg-card px-3 py-1 text-sm font-semibold";

/** What OCR noticed besides the text: the app, the sender and a payment receipt. */
function ScreenshotChips({ source }: { source: ScreenshotSource }) {
  const app = source.app && source.app !== "other" ? SCREENSHOT_APP_LABEL[source.app] : null;
  if (!app && !source.sender && !source.isPaymentReceipt) {
    return <p className="text-sm text-ink-muted">We read the text in your screenshot below.</p>;
  }
  return (
    <div className="min-w-0">
      <p className="text-sm font-bold text-ink-muted">What we noticed</p>
      <ul className="mt-2 flex flex-wrap gap-2">
        {app && (
          <li className={chipClass}>
            <AppWindow aria-hidden className="size-4 shrink-0 text-accent" />
            {app}
          </li>
        )}
        {source.sender && (
          <li className={chipClass}>
            <UserRound aria-hidden className="size-4 shrink-0 text-accent" />
            <span className="min-w-0 [overflow-wrap:anywhere]">
              From: <span className="font-mono">{source.sender}</span>
            </span>
          </li>
        )}
        {source.isPaymentReceipt && (
          <li className={chipClass}>
            <ReceiptIndianRupee aria-hidden className="size-4 shrink-0 text-accent" />
            Looks like a payment receipt
          </li>
        )}
      </ul>
    </div>
  );
}

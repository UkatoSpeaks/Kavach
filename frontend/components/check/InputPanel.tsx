"use client";

import { useId, useRef, type FormEvent, type KeyboardEvent, type RefObject } from "react";
import { Link2, MessageSquareText, QrCode, ScanSearch, IndianRupee, X } from "lucide-react";
import {
  LINK_EXAMPLES,
  MESSAGE_EXAMPLES,
  QR_EXAMPLES,
  UPI_EXAMPLES,
  type Example,
} from "@/lib/examples";
import { cn } from "@/lib/cn";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { ExampleChips } from "./ExampleChips";
import { LineField, linkHint, upiHint } from "./LineField";
import { MessageField } from "./MessageField";
import { QrField } from "./QrField";

export type Tab = "text" | "url" | "upi" | "qr";

export const TABS: { id: Tab; label: string; Icon: typeof Link2; examples: Example[] }[] = [
  { id: "text", label: "Message", Icon: MessageSquareText, examples: MESSAGE_EXAMPLES },
  { id: "url", label: "Link", Icon: Link2, examples: LINK_EXAMPLES },
  { id: "upi", label: "UPI ID", Icon: IndianRupee, examples: UPI_EXAMPLES },
  { id: "qr", label: "QR code", Icon: QrCode, examples: QR_EXAMPLES },
];

export type InputValues = {
  text: string;
  url: string;
  upi: string;
  qrFile: File | null;
  qrPreview: string | null;
};

type InputPanelProps = {
  tab: Tab;
  onTabChange: (tab: Tab) => void;
  values: InputValues;
  onValueChange: (tab: Exclude<Tab, "qr">, value: string) => void;
  onQrChange: (file: File | null) => void;
  onSubmit: () => void;
  onCancel: () => void;
  onExample: (tab: Tab, example: Example) => void;
  loading: boolean;
  fieldRef: RefObject<HTMLTextAreaElement | HTMLInputElement | null>;
};

export function isReady(tab: Tab, values: InputValues): boolean {
  switch (tab) {
    case "text":
      return values.text.trim().length > 0;
    case "url":
      return values.url.trim().length > 0;
    case "upi":
      return values.upi.trim().length > 0;
    case "qr":
      return values.qrFile !== null;
  }
}

/** The four input tabs, the submit button and the scanning overlay. */
export function InputPanel({
  tab,
  onTabChange,
  values,
  onValueChange,
  onQrChange,
  onSubmit,
  onCancel,
  onExample,
  loading,
  fieldRef,
}: InputPanelProps) {
  const id = useId();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const active = TABS.find((t) => t.id === tab)!;
  const ready = isReady(tab, values);

  function onTabKey(e: KeyboardEvent, index: number) {
    const last = TABS.length - 1;
    const next =
      e.key === "ArrowRight" ? (index === last ? 0 : index + 1)
      : e.key === "ArrowLeft" ? (index === 0 ? last : index - 1)
      : e.key === "Home" ? 0
      : e.key === "End" ? last
      : null;
    if (next === null) return;
    e.preventDefault();
    onTabChange(TABS[next].id);
    tabRefs.current[next]?.focus();
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (ready && !loading) onSubmit();
  }

  function onFormKey(e: KeyboardEvent) {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      if (ready && !loading) onSubmit();
    }
  }

  return (
    <Card className="overflow-hidden">
      <div
        role="tablist"
        aria-label="What do you want to check?"
        className="grid grid-cols-4 border-b-2 border-ink bg-paper"
      >
        {TABS.map((t, i) => {
          const selected = t.id === tab;
          return (
            <button
              key={t.id}
              ref={(el) => {
                tabRefs.current[i] = el;
              }}
              type="button"
              role="tab"
              id={`${id}-tab-${t.id}`}
              aria-selected={selected}
              aria-controls={`${id}-panel`}
              tabIndex={selected ? 0 : -1}
              disabled={loading && !selected}
              onClick={() => onTabChange(t.id)}
              onKeyDown={(e) => onTabKey(e, i)}
              className={cn(
                "flex min-h-16 flex-col items-center justify-center gap-1 px-1 py-2 text-sm leading-tight font-bold transition-colors",
                "border-ink not-last:border-r-2 focus-visible:-outline-offset-4",
                selected ? "bg-card text-accent-dark shadow-[inset_0_-4px_0_var(--color-accent)]" : "text-ink-muted hover:bg-accent-tint hover:text-ink",
                "disabled:opacity-50",
              )}
            >
              <t.Icon aria-hidden className="size-5" />
              {t.label}
            </button>
          );
        })}
      </div>

      <form
        id={`${id}-panel`}
        role="tabpanel"
        aria-labelledby={`${id}-tab-${tab}`}
        onSubmit={submit}
        onKeyDown={onFormKey}
        className="p-4 sm:p-6"
      >
        <div className="relative">
          {tab === "text" && (
            <MessageField
              value={values.text}
              onChange={(v) => onValueChange("text", v)}
              disabled={loading}
              inputRef={fieldRef as RefObject<HTMLTextAreaElement | null>}
            />
          )}
          {tab === "url" && (
            <LineField
              label="Paste the link"
              value={values.url}
              onChange={(v) => onValueChange("url", v)}
              placeholder="e.g. sbi-kyc-update.top/verify"
              hint={linkHint(values.url)}
              help="Just the link. We check where it really goes, its age and blocklists."
              inputMode="url"
              disabled={loading}
              inputRef={fieldRef as RefObject<HTMLInputElement | null>}
            />
          )}
          {tab === "upi" && (
            <LineField
              label="Enter the UPI ID"
              value={values.upi}
              onChange={(v) => onValueChange("upi", v)}
              placeholder="e.g. name@okaxis"
              hint={upiHint(values.upi)}
              help="Like name@okaxis — or paste a upi://pay link."
              inputMode="email"
              disabled={loading}
              inputRef={fieldRef as RefObject<HTMLInputElement | null>}
            />
          )}
          {tab === "qr" && (
            <QrField
              file={values.qrFile}
              previewUrl={values.qrPreview}
              onChange={onQrChange}
              disabled={loading}
            />
          )}

          {loading && (
            <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden rounded-xl">
              <div className="absolute inset-0 bg-accent/5" />
              <div className="absolute inset-x-0 h-12 -translate-y-full animate-scan bg-linear-to-b from-transparent to-accent/25">
                <div className="absolute inset-x-0 bottom-0 h-0.5 bg-accent" />
              </div>
            </div>
          )}
        </div>

        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-center">
          {/* Distinct keys: if React reused the Cancel <button> as the submit button, the
              click that cancels would then submit the form and start the check again. */}
          {loading ? (
            <Button
              key="cancel"
              variant="secondary"
              size="lg"
              className="w-full sm:w-auto"
              onClick={onCancel}
              icon={<X aria-hidden className="order-first size-5" />}
            >
              Cancel
            </Button>
          ) : (
            <Button
              key="submit"
              type="submit"
              size="lg"
              className="w-full whitespace-nowrap sm:w-auto"
              disabled={!ready}
              icon={<ScanSearch aria-hidden className="order-first size-5" />}
            >
              Check now
            </Button>
          )}
          <p className="hidden text-sm text-ink-muted sm:block">
            or press <kbd className="rounded border-2 border-ink/40 px-1 font-mono text-xs">Ctrl</kbd>/<kbd className="rounded border-2 border-ink/40 px-1 font-mono text-xs">⌘</kbd>
            {" + "}
            <kbd className="rounded border-2 border-ink/40 px-1 font-mono text-xs">Enter</kbd>
          </p>
        </div>

        <ExampleChips
          className="mt-6 border-t-2 border-dashed border-ink/20 pt-4"
          examples={active.examples}
          onPick={(ex) => onExample(tab, ex)}
          disabled={loading}
        />
      </form>
    </Card>
  );
}

"use client";

import { useId, useState, useSyncExternalStore, type RefObject } from "react";
import { ClipboardPaste } from "lucide-react";
import { cn } from "@/lib/cn";

export const MAX_MESSAGE_CHARS = 5000;

const noop = () => () => {};

/** Clipboard reading needs a secure context and isn't in every browser (false on the server). */
function useCanPaste(): boolean {
  return useSyncExternalStore(
    noop,
    () => typeof navigator.clipboard?.readText === "function",
    () => false,
  );
}

type MessageFieldProps = {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  inputRef?: RefObject<HTMLTextAreaElement | null>;
};

export function MessageField({ value, onChange, disabled, inputRef }: MessageFieldProps) {
  const id = useId();
  const canPaste = useCanPaste();
  const [pasteNote, setPasteNote] = useState<string | null>(null);
  const count = value.length;
  const nearLimit = count > MAX_MESSAGE_CHARS * 0.9;

  async function paste() {
    setPasteNote(null);
    try {
      const text = await navigator.clipboard.readText();
      if (!text.trim()) {
        setPasteNote("Your clipboard is empty. Copy the message first.");
        return;
      }
      onChange(text.slice(0, MAX_MESSAGE_CHARS));
      if (text.length > MAX_MESSAGE_CHARS) {
        setPasteNote(`Only the first ${MAX_MESSAGE_CHARS.toLocaleString("en-IN")} characters fit.`);
      }
      inputRef?.current?.focus();
    } catch {
      setPasteNote("Couldn't read the clipboard. Long-press the box and choose Paste instead.");
    }
  }

  return (
    <div>
      <div className="flex items-end justify-between gap-3">
        <label htmlFor={id} className="font-bold">
          Paste the suspicious message
        </label>
        {canPaste && (
          <button
            type="button"
            onClick={paste}
            disabled={disabled}
            className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border-2 border-ink bg-card px-3 text-sm font-bold shadow-brutal-sm hover:bg-accent-tint active:translate-y-0.5 active:shadow-none disabled:opacity-50"
          >
            <ClipboardPaste aria-hidden className="size-4" />
            Paste
          </button>
        )}
      </div>
      <textarea
        ref={inputRef}
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        maxLength={MAX_MESSAGE_CHARS}
        disabled={disabled}
        rows={8}
        aria-describedby={`${id}-count ${id}-hint`}
        placeholder="e.g. Dear customer, your account will be blocked today. Update KYC at…"
        className="mt-2 block min-h-48 w-full resize-y rounded-xl border-2 border-ink bg-card px-4 py-3 placeholder:text-ink-muted/70 focus-visible:outline-offset-2 disabled:opacity-70"
      />
      <div className="mt-1.5 flex items-start justify-between gap-3 text-sm">
        <p id={`${id}-hint`} className="text-ink-muted" aria-live="polite">
          {pasteNote ?? "Include links, numbers and UPI IDs — they matter."}
        </p>
        <p
          id={`${id}-count`}
          className={cn("shrink-0 tabular-nums", nearLimit ? "font-bold text-ink" : "text-ink-muted")}
        >
          {count.toLocaleString("en-IN")} / {MAX_MESSAGE_CHARS.toLocaleString("en-IN")}
          <span className="sr-only"> characters</span>
        </p>
      </div>
    </div>
  );
}

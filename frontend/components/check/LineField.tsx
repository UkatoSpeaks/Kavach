"use client";

import { useId, type ReactNode, type RefObject } from "react";
import { Info } from "lucide-react";

type LineFieldProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  /** A light format hint for the current value, or null when it looks fine. */
  hint: ReactNode;
  help: string;
  inputMode?: "url" | "email" | "text";
  disabled?: boolean;
  inputRef?: RefObject<HTMLInputElement | null>;
};

/** Single-line input (link, UPI ID) with a live, non-blocking format hint. */
export function LineField({
  label,
  value,
  onChange,
  placeholder,
  hint,
  help,
  inputMode = "text",
  disabled,
  inputRef,
}: LineFieldProps) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="font-bold">
        {label}
      </label>
      <input
        ref={inputRef}
        id={id}
        type="text"
        inputMode={inputMode}
        autoComplete="off"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        enterKeyHint="go"
        maxLength={2048}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        placeholder={placeholder}
        aria-describedby={`${id}-hint`}
        className="mt-2 block min-h-14 w-full rounded-xl border-2 border-ink bg-card px-4 font-mono text-base placeholder:font-sans placeholder:text-ink-muted/70 disabled:opacity-70"
      />
      <div id={`${id}-hint`} aria-live="polite" className="mt-1.5 text-sm">
        {hint ? (
          <p className="flex gap-1.5 font-semibold text-accent-dark">
            <Info aria-hidden className="mt-0.5 size-4 shrink-0" />
            <span>{hint}</span>
          </p>
        ) : (
          <p className="text-ink-muted">{help}</p>
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ format hints

const UPI_ID = /^[a-z0-9][a-z0-9._+-]{0,63}@[a-z][a-z0-9-]+$/i;

export function linkHint(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  if (/^upi:/i.test(v)) return "That's a UPI payment link — check it in the UPI ID tab.";
  if (/\s/.test(v)) return "This looks like more than a link. Paste whole messages in the Message tab.";
  if (!/[a-z0-9-]\.[a-z]{2,}/i.test(v)) return "A link usually looks like example.com/page.";
  return null;
}

export function upiHint(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  if (/^upi:\/\//i.test(v)) return v.includes("pa=") ? null : "A UPI payment link needs a pa=name@bank part.";
  if (/\s/.test(v)) return "A UPI ID has no spaces, like name@okaxis.";
  if (!v.includes("@")) return "A UPI ID looks like name@bank, e.g. shopname@okaxis.";
  const handle = v.split("@")[1] ?? "";
  if (handle.includes(".")) {
    return "That looks like an email address. UPI IDs end in a bank handle like @ybl or @okaxis.";
  }
  if (!UPI_ID.test(v)) return "A UPI ID looks like name@bank, e.g. shopname@okaxis.";
  return null;
}

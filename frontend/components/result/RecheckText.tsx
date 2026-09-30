"use client";

import { useId, useState, type FormEvent } from "react";
import { ScanText } from "lucide-react";
import { MAX_MESSAGE_CHARS } from "@/components/check/MessageField";
import { Button } from "@/components/ui/Button";
import { SectionTitle } from "./SectionTitle";

type RecheckTextProps = {
  /** The text OCR read from the screenshot. */
  text: string;
  onRecheck: (text: string) => void;
};

/** The text read from a screenshot, editable, so people can fix OCR mistakes and check again. */
export function RecheckText({ text, onRecheck }: RecheckTextProps) {
  const id = useId();
  const [value, setValue] = useState(text.slice(0, MAX_MESSAGE_CHARS));
  const ready = value.trim().length > 0;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (ready) onRecheck(value);
  }

  return (
    <section>
      <SectionTitle>
        <label htmlFor={id}>Text we read from your screenshot</label>
      </SectionTitle>
      <p id={`${id}-hint`} className="mt-1 text-sm text-ink-muted">
        Our reader can make mistakes. Fix anything it got wrong, then check the text again.
      </p>
      <form onSubmit={submit}>
        <textarea
          id={id}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          maxLength={MAX_MESSAGE_CHARS}
          rows={6}
          aria-describedby={`${id}-hint`}
          placeholder="No text was read. Type the message here to check it."
          className="mt-3 block min-h-36 w-full resize-y rounded-xl border-2 border-ink bg-card px-4 py-3 placeholder:text-ink-muted/70 focus-visible:outline-offset-2"
        />
        <Button
          type="submit"
          size="sm"
          variant="secondary"
          className="mt-3"
          disabled={!ready}
          icon={<ScanText aria-hidden className="order-first size-4" />}
        >
          Re-check this text
        </Button>
      </form>
    </section>
  );
}

"use client";

import { useId } from "react";
import type { Lang } from "@/lib/useExplanationLang";
import { cn } from "@/lib/cn";
import { SectionTitle } from "./SectionTitle";

type ExplanationProps = {
  en: string;
  hi: string;
  lang: Lang;
  onLangChange: (lang: Lang) => void;
};

const OPTIONS: { value: Lang; label: string; htmlLang: string }[] = [
  { value: "en", label: "English", htmlLang: "en" },
  { value: "hi", label: "हिंदी", htmlLang: "hi" },
];

/** The explanation, with an English / हिंदी switch (the choice is remembered). */
export function Explanation({ en, hi, lang, onLangChange }: ExplanationProps) {
  const id = useId();
  const shown = lang === "hi" && hi ? "hi" : "en";
  const text = shown === "hi" ? hi : en;
  if (!en && !hi) return null;

  return (
    <section aria-labelledby={`${id}-title`}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <SectionTitle id={`${id}-title`}>Why</SectionTitle>
        <div
          role="group"
          aria-label="Explanation language"
          className="inline-flex rounded-full border-2 border-ink bg-card p-0.5 shadow-brutal-sm"
        >
          {OPTIONS.map((o) => (
            <button
              key={o.value}
              type="button"
              lang={o.htmlLang}
              aria-pressed={lang === o.value}
              onClick={() => onLangChange(o.value)}
              className={cn(
                "min-h-9 rounded-full px-4 text-sm font-bold transition-colors",
                lang === o.value ? "bg-ink text-paper" : "hover:bg-accent-tint",
              )}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>
      <p lang={shown} className={cn("mt-3 text-pretty", shown === "hi" && "font-hindi text-lg")}>
        {text}
      </p>
    </section>
  );
}

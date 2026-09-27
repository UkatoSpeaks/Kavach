import { ShieldCheck, Sparkles } from "lucide-react";
import type { Example } from "@/lib/examples";
import { cn } from "@/lib/cn";

type ExampleChipsProps = {
  examples: Example[];
  onPick: (example: Example) => void;
  disabled?: boolean;
  className?: string;
};

/** "Try an example" chips. Genuine examples are marked, so people know to expect SAFE. */
export function ExampleChips({ examples, onPick, disabled, className }: ExampleChipsProps) {
  return (
    <div className={className}>
      <p className="flex items-center gap-1.5 text-sm font-bold text-ink-muted">
        <Sparkles aria-hidden className="size-4 text-accent" />
        Try an example
      </p>
      <ul className="mt-2 flex flex-wrap gap-2">
        {examples.map((ex) => (
          <li key={ex.label}>
            <button
              type="button"
              disabled={disabled}
              onClick={() => onPick(ex)}
              className={cn(
                "inline-flex min-h-10 items-center gap-1.5 rounded-full border-2 border-ink px-3 py-1 text-sm font-semibold",
                "shadow-brutal-sm transition-[transform,box-shadow,background-color] duration-100",
                "hover:-translate-y-px hover:bg-accent-tint active:translate-y-0.5 active:shadow-none",
                "disabled:pointer-events-none disabled:opacity-50",
                ex.genuine ? "bg-paper" : "bg-card",
              )}
            >
              {ex.genuine && <ShieldCheck aria-hidden className="size-4 text-accent" />}
              {ex.label}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

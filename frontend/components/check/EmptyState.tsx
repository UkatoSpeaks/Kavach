import { Link2, MessageSquareText, ScanLine, ShieldCheck, Smartphone } from "lucide-react";
import type { Example } from "@/lib/examples";
import { MESSAGE_EXAMPLES } from "@/lib/examples";
import { Card } from "@/components/ui/Card";
import { ExampleChips } from "./ExampleChips";

const TIPS = [
  { Icon: MessageSquareText, text: "Paste the full message, including links and numbers." },
  { Icon: Link2, text: "Got just a link or UPI ID? Use the Link or UPI ID tab." },
  { Icon: ScanLine, text: "Asked to scan a QR code? Upload a photo or screenshot of it." },
  { Icon: Smartphone, text: "Easier to screenshot than copy? Use the Screenshot tab." },
];

/** The result column before any check: short guidance and examples, not a blank box. */
export function EmptyState({ onPick }: { onPick: (example: Example) => void }) {
  return (
    <Card tone="paper" className="border-dashed p-5 shadow-none sm:p-6">
      <p className="flex items-center gap-2 font-display text-2xl font-extrabold">
        <ShieldCheck aria-hidden className="size-7 text-accent" />
        Your result will appear here
      </p>
      <ul className="mt-4 flex flex-col gap-3">
        {TIPS.map(({ Icon, text }) => (
          <li key={text} className="flex gap-3">
            <Icon aria-hidden className="mt-1 size-5 shrink-0 text-accent" />
            <span>{text}</span>
          </li>
        ))}
      </ul>
      <p className="mt-4 text-sm text-ink-muted">
        You&apos;ll get a verdict, the warning signs highlighted in your message, and what to do
        next — in English and हिंदी.
      </p>
      <ExampleChips
        className="mt-5"
        examples={MESSAGE_EXAMPLES.filter((e, i) => i < 4 || e.genuine)}
        onPick={onPick}
      />
    </Card>
  );
}

import type { LucideIcon } from "lucide-react";
import { ArrowDown, Globe, IndianRupee, ListChecks, Sparkles, Users } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";

type Check = { icon: LucideIcon; title: string; sub?: string; body: string };

const CHECKS: Check[] = [
  {
    icon: ListChecks,
    title: "Scam-pattern rules",
    body: "Looks for tricks scammers reuse: threats, urgency, “enter PIN to receive”, fake refunds.",
  },
  {
    icon: Globe,
    title: "Link check",
    sub: "Domain age & lookalikes",
    body: "Where does the link really go? Is the website brand new, or pretending to be a bank?",
  },
  {
    icon: IndianRupee,
    title: "UPI ID check",
    body: "Does the UPI ID pose as a bank, brand or “refund desk”? Banks never collect money through a personal UPI ID.",
  },
  {
    icon: Users,
    title: "Community reports",
    body: "Has someone already reported this number, UPI ID or link as a scam?",
  },
  {
    icon: Sparkles,
    title: "AI explanation",
    body: "An AI reads the whole message and explains the result in simple English and Hindi.",
  },
];

const BANDS = [
  { label: "Safe", range: "0–34", className: "bg-safe-tint text-safe-deep" },
  {
    label: "Suspicious",
    range: "35–69",
    className: "bg-suspicious-tint text-suspicious-deep",
  },
  { label: "Scam", range: "70–100", className: "bg-scam-tint text-scam-deep" },
];

export function HowItWorks() {
  return (
    <section id="how" aria-labelledby="how-title" className="bg-card py-16 sm:py-20 border-y-2 border-ink">
      <Container>
        <SectionHeading
          id="how-title"
          eyebrow="How Kavach decides"
          title="Five independent checks. One clear score."
          intro="Each check looks at your message in its own way and gives its own score. Kavach adds them up — and shows you exactly how much each one counted."
        />

        <ol className="mt-10 grid gap-5 sm:grid-cols-2 lg:grid-cols-5 lg:gap-4">
          {CHECKS.map(({ icon: Icon, title, sub, body }, i) => (
            <Card as="li" key={title} className="flex flex-col gap-3 p-5 sm:last:col-span-2 lg:last:col-span-1">
              <div className="flex items-center gap-3">
                <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border-2 border-ink bg-accent-tint text-accent-dark">
                  <Icon aria-hidden className="size-5" />
                </span>
                <span className="font-display text-sm font-bold text-ink-muted">
                  Check {i + 1}
                </span>
              </div>
              <h3 className="font-display text-lg leading-snug font-extrabold">
                {title}
                {sub && <span className="block text-sm font-semibold text-accent">{sub}</span>}
              </h3>
              <p className="text-sm text-ink-muted">{body}</p>
            </Card>
          ))}
        </ol>

        <div aria-hidden="true" className="flex justify-center py-5">
          <ArrowDown className="size-9" strokeWidth={2.5} />
        </div>

        <Card tone="paper" className="mx-auto max-w-3xl p-6 sm:p-8">
          <h3 className="font-display text-2xl font-extrabold sm:text-3xl">
            One risk score, 0 to 100
          </h3>
          <div className="mt-5 flex h-4 overflow-hidden rounded-full border-2 border-ink" aria-hidden="true">
            <div className="w-[35%] bg-safe" />
            <div className="w-[35%] border-x-2 border-ink bg-suspicious" />
            <div className="w-[30%] bg-scam" />
          </div>
          <ul className="mt-4 grid grid-cols-3 gap-2 text-center sm:gap-3">
            {BANDS.map((b) => (
              <li key={b.label} className={`rounded-xl border-2 border-ink px-2 py-2 ${b.className}`}>
                <span className="block font-bold">{b.label}</span>
                <span className="block text-sm">{b.range}</span>
              </li>
            ))}
          </ul>
          <p className="mt-6 flex items-start gap-3 rounded-xl border-2 border-ink bg-accent-tint p-4 font-semibold">
            <Sparkles aria-hidden className="mt-1 size-5 shrink-0 text-accent-dark" />
            The AI explains the verdict — it never decides alone.
          </p>
        </Card>
      </Container>
    </section>
  );
}

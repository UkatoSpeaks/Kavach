import { Container } from "@/components/ui/Container";

// Only numbers we measured ourselves (see backend/ml/reports). Don't add others.
const STATS = [
  {
    value: "0.02%",
    label: "false alarms on 4,473 real messages",
    note: "UCI SMS benchmark",
  },
  { value: "5", label: "independent checks", note: "each with its own score" },
  { value: "English + हिंदी", label: "explanations", note: "in plain words" },
];

export function TrustStrip() {
  return (
    <section aria-label="Kavach in numbers" className="border-y-2 border-ink bg-ink text-paper">
      <Container as="ul" className="grid gap-8 py-10 sm:grid-cols-3 sm:gap-6">
        {STATS.map((s) => (
          <li key={s.label} className="text-center sm:text-left">
            <p className="font-display text-4xl leading-tight font-extrabold">{s.value}</p>
            <p className="mt-1 font-semibold">{s.label}</p>
            <p className="text-sm text-paper/75">{s.note}</p>
          </li>
        ))}
      </Container>
    </section>
  );
}

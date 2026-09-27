import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Container } from "@/components/ui/Container";

export function FinalCta() {
  return (
    <section aria-labelledby="cta-title" className="py-16 sm:py-24">
      <Container>
        <Card
          tone="accent"
          className="flex flex-col items-start gap-6 p-6 shadow-brutal-lg sm:p-10 md:flex-row md:items-center md:justify-between"
        >
          <h2
            id="cta-title"
            className="max-w-xl font-display text-3xl leading-tight font-extrabold text-balance sm:text-4xl"
          >
            Got a suspicious message? Check it before you pay.
          </h2>
          <Button
            href="/check"
            size="lg"
            className="w-full shrink-0 sm:w-auto"
            icon={<ArrowRight aria-hidden className="size-5" />}
          >
            Check a message
          </Button>
        </Card>
      </Container>
    </section>
  );
}

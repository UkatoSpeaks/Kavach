import { ArrowRight, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Container } from "@/components/ui/Container";
import { DemoCard } from "./DemoCard";

export function Hero() {
  return (
    <section aria-labelledby="hero-title" className="pt-10 pb-16 sm:pt-16 lg:pt-20 lg:pb-24">
      <Container className="grid items-center gap-12 lg:grid-cols-[1.1fr_1fr] lg:gap-16">
        <div>
          <Badge icon={<ShieldCheck aria-hidden className="size-4 text-accent" />}>
            AI SCAM CHECKER FOR INDIA
          </Badge>

          <h1
            id="hero-title"
            className="mt-6 font-display text-[2.6rem] leading-[1.08] font-extrabold tracking-tight text-balance sm:text-6xl lg:text-7xl"
          >
            Pehle{" "}
            <span className="inline-block -rotate-2 rounded-xl border-2 border-ink bg-accent px-2 text-white shadow-brutal-sm">
              check
            </span>{" "}
            karo, phir pay karo.
          </h1>

          <p className="mt-6 max-w-xl text-lg text-ink-muted text-pretty sm:text-xl sm:leading-relaxed">
            Paste any SMS, WhatsApp message, link, UPI ID or QR code — or just upload a screenshot.
            Kavach tells you in seconds if it&apos;s a scam — and exactly why — in English and Hindi.
          </p>

          <div className="mt-8 flex flex-col gap-4 sm:flex-row">
            <Button
              href="/check"
              size="lg"
              icon={<ArrowRight aria-hidden className="size-5" />}
            >
              Check a message
            </Button>
            <Button href="#how" size="lg" variant="secondary">
              How it works
            </Button>
          </div>
        </div>

        <DemoCard />
      </Container>
    </section>
  );
}

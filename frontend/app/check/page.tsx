import type { Metadata } from "next";
import { ArrowLeft, Construction } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Container } from "@/components/ui/Container";
import { Footer } from "@/components/site/Footer";
import { Navbar } from "@/components/site/Navbar";
import { WarmUp } from "@/components/site/WarmUp";

export const metadata: Metadata = {
  title: "Check a message",
  description: "Check an SMS, WhatsApp message, link, UPI ID or QR code for scams.",
};

// Placeholder: the real checker comes next.
export default function CheckPage() {
  return (
    <>
      <WarmUp />
      <Navbar />
      <main id="main" className="flex-1 py-16 sm:py-24">
        <Container className="max-w-2xl">
          <Card className="p-6 text-center sm:p-10">
            <span className="mx-auto flex size-14 items-center justify-center rounded-xl border-2 border-ink bg-accent-tint text-accent-dark">
              <Construction aria-hidden className="size-7" />
            </span>
            <h1 className="mt-5 font-display text-3xl font-extrabold sm:text-4xl">
              Checker coming in the next step
            </h1>
            <p className="mt-3 text-lg text-ink-muted">
              Soon you&apos;ll be able to paste a message, link, UPI ID or QR code here.
            </p>
            <Button
              href="/"
              variant="secondary"
              className="mt-8"
              icon={<ArrowLeft aria-hidden className="order-first size-5" />}
            >
              Back to home
            </Button>
          </Card>
        </Container>
      </main>
      <Footer />
    </>
  );
}

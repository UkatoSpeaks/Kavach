import type { Metadata } from "next";
import { Checker } from "@/components/check/Checker";
import { Container } from "@/components/ui/Container";
import { Footer } from "@/components/site/Footer";
import { Navbar } from "@/components/site/Navbar";
import { WarmUp } from "@/components/site/WarmUp";

export const metadata: Metadata = {
  title: "Check a message",
  description: "Check an SMS, WhatsApp message, link, UPI ID or QR code for scams.",
  alternates: { canonical: "/check" },
};

export default function CheckPage() {
  return (
    <>
      <WarmUp />
      <Navbar />
      <main id="main" className="flex-1 pt-8 pb-16 sm:pt-12 sm:pb-24">
        <Container>
          <div className="max-w-2xl">
            <h1 className="font-display text-4xl leading-tight font-extrabold tracking-tight text-balance sm:text-5xl">
              Check before you pay
            </h1>
            <p className="mt-2 text-lg text-ink-muted text-pretty">
              Paste a message, link or UPI ID, or upload a QR code. You&apos;ll see if it&apos;s a
              scam — and exactly why.
            </p>
          </div>
          <div className="mt-8">
            <Checker />
          </div>
        </Container>
      </main>
      <Footer />
    </>
  );
}

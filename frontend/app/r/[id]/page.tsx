import type { Metadata } from "next";
import { SharedResult } from "@/components/result/SharedResult";
import { Container } from "@/components/ui/Container";
import { Footer } from "@/components/site/Footer";
import { Navbar } from "@/components/site/Navbar";
import { WarmUp } from "@/components/site/WarmUp";

export const metadata: Metadata = {
  title: "Scam check result",
  description: "A message checked with Kavach: the verdict, the warning signs and what to do.",
  // Results are private to whoever has the link.
  robots: { index: false, follow: false },
};

/**
 * A shared result. Loaded in the browser, not on the server: the free API server may need up
 * to a minute to wake up, and the browser can show that instead of a blank page.
 */
export default async function SharedResultPage({ params }: PageProps<"/r/[id]">) {
  const { id } = await params;
  return (
    <>
      <WarmUp />
      <Navbar />
      <main id="main" className="flex-1 pt-8 pb-16 sm:pt-12 sm:pb-24">
        <Container className="max-w-3xl">
          <SharedResult id={id} />
        </Container>
      </main>
      <Footer />
    </>
  );
}

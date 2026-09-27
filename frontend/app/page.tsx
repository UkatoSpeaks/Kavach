import { CommonScams } from "@/components/landing/CommonScams";
import { FinalCta } from "@/components/landing/FinalCta";
import { Hero } from "@/components/landing/Hero";
import { HowItWorks } from "@/components/landing/HowItWorks";
import { TrustStrip } from "@/components/landing/TrustStrip";
import { WhatWeCheck } from "@/components/landing/WhatWeCheck";
import { Footer } from "@/components/site/Footer";
import { Navbar } from "@/components/site/Navbar";
import { WarmUp } from "@/components/site/WarmUp";

export default function Home() {
  return (
    <>
      <WarmUp />
      <Navbar />
      <main id="main" className="flex-1">
        <Hero />
        <WhatWeCheck />
        <HowItWorks />
        <CommonScams />
        <TrustStrip />
        <FinalCta />
      </main>
      <Footer />
    </>
  );
}

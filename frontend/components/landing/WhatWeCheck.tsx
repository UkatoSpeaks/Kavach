import type { LucideIcon } from "lucide-react";
import { Image as ImageIcon, IndianRupee, Link2, MessageCircle, MessageSquareText, QrCode } from "lucide-react";
import { Badge } from "@/components/ui/Badge";
import { Card } from "@/components/ui/Card";
import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";
import { cn } from "@/lib/cn";

type Item = { icon: LucideIcon; title: string; body: string; soon?: boolean };

const ITEMS: Item[] = [
  {
    icon: MessageSquareText,
    title: "Messages",
    body: "Paste the text of any SMS or WhatsApp message you're unsure about.",
  },
  {
    icon: Link2,
    title: "Links",
    body: "Short links are opened safely to see where they really go, before you tap.",
  },
  {
    icon: IndianRupee,
    title: "UPI IDs",
    body: "Spot UPI IDs and payment requests pretending to be a bank, brand or refund desk.",
  },
  {
    icon: QrCode,
    title: "QR codes",
    body: "Upload a QR code to see who it really pays — before you scan it in your UPI app.",
  },
  {
    icon: ImageIcon,
    title: "Screenshots",
    body: "Share a screenshot of a chat or SMS and get the same check.",
    soon: true,
  },
  {
    icon: MessageCircle,
    title: "WhatsApp bot",
    body: "Forward a suspicious message to Kavach on WhatsApp and get a reply.",
    soon: true,
  },
];

export function WhatWeCheck() {
  return (
    <section aria-labelledby="checks-title" className="py-16 sm:py-20">
      <Container>
        <SectionHeading
          id="checks-title"
          eyebrow="What Kavach checks"
          title="Anything a scammer sends you"
          intro="Copy it, paste it, and get a clear answer before you reply, click or pay."
        />
        <ul className="mt-10 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {ITEMS.map(({ icon: Icon, title, body, soon }) => (
            <Card
              as="li"
              key={title}
              tone={soon ? "paper" : "white"}
              className={cn("flex flex-col gap-3 p-6", soon && "border-dashed shadow-none")}
            >
              <div className="flex items-center justify-between gap-3">
                <span
                  className={cn(
                    "flex size-12 items-center justify-center rounded-xl border-2 border-ink",
                    soon ? "bg-card text-ink-muted" : "bg-accent-tint text-accent-dark",
                  )}
                >
                  <Icon aria-hidden className="size-6" />
                </span>
                {soon && <Badge tone="ink">Coming soon</Badge>}
              </div>
              <h3 className="font-display text-xl font-extrabold">{title}</h3>
              <p className="text-ink-muted">{body}</p>
            </Card>
          ))}
        </ul>
      </Container>
    </section>
  );
}

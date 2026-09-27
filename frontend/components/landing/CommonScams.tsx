import type { LucideIcon } from "lucide-react";
import { BriefcaseBusiness, Headset, KeyRound, Link2Off, QrCode, Undo2 } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Container } from "@/components/ui/Container";
import { SectionHeading } from "@/components/ui/SectionHeading";

type Scam = { icon: LucideIcon; title: string; how: string; example: string; remember: string };

// Example lines are illustrative; numbers and links are masked so none of them are real.
const SCAMS: Scam[] = [
  {
    icon: KeyRound,
    title: "“Enter PIN to receive money”",
    how: "You get a UPI request or a message saying you must approve it and enter your PIN to receive a prize, cashback or payment.",
    example: "“₹5,000 cashback credited! Approve the request and enter UPI PIN to receive.”",
    remember: "You never need your UPI PIN to receive money. Entering your PIN always sends money out.",
  },
  {
    icon: QrCode,
    title: "QR code scam",
    how: "A “buyer” on a selling site sends a QR code and asks you to scan it to receive their payment.",
    example: "“I’ve sent the QR for your sofa payment. Just scan it and enter PIN.”",
    remember: "Scanning a QR code is for paying, never for receiving money.",
  },
  {
    icon: Undo2,
    title: "“Sent by mistake” refund",
    how: "You get a fake “money credited” SMS, then a call or message asking you to urgently send the money back.",
    example: "“Sorry, I sent ₹10,000 to your number by mistake. Please return it, it’s urgent.”",
    remember: "Check your bank app, not the SMS. Don’t send anything back yourself — talk to your bank.",
  },
  {
    icon: Link2Off,
    title: "Fake KYC, bill or e-challan links",
    how: "An SMS warns your bank account will be blocked, your power will be cut or a traffic fine is pending — and gives a link to fix it.",
    example: "“Your e-challan of ₹500 is pending. Pay today to avoid court action: bit.ly/xxxxx”",
    remember: "Don’t pay or update KYC through SMS links. Open the official app or website yourself.",
  },
  {
    icon: BriefcaseBusiness,
    title: "Task-based job scam",
    how: "You’re offered easy money for liking videos or rating hotels. After small payouts, you’re asked to pay to unlock bigger tasks.",
    example: "“Part-time job! Earn ₹3,000 a day liking YouTube videos. Message us on Telegram.”",
    remember: "A real job never asks you to pay money to earn money.",
  },
  {
    icon: Headset,
    title: "Fake customer care",
    how: "Fake helpline numbers appear in search results or social media. The “agent” asks you to install an app, share your screen or pay a small fee.",
    example: "“Refund stuck? Call our 24x7 customer care: 98XXXXXXXX”",
    remember: "Take helpline numbers only from the official app or website. Never install apps an agent asks for.",
  },
];

export function CommonScams() {
  return (
    <section id="scams" aria-labelledby="scams-title" className="py-16 sm:py-20">
      <Container>
        <SectionHeading
          id="scams-title"
          eyebrow="Common scams in India"
          title="Know the tricks before they reach you"
          intro="Most UPI and link scams follow a handful of scripts. Once you know them, they are much easier to spot."
        />
        <ul className="mt-10 grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {SCAMS.map(({ icon: Icon, title, how, example, remember }) => (
            <Card as="li" key={title} className="flex flex-col p-6">
              <span className="flex size-12 items-center justify-center rounded-xl border-2 border-ink bg-accent-tint text-accent-dark">
                <Icon aria-hidden className="size-6" />
              </span>
              <h3 className="mt-4 font-display text-xl leading-snug font-extrabold">{title}</h3>
              <p className="mt-2 text-ink-muted">{how}</p>
              <p className="mt-4 rounded-xl border-2 border-dashed border-ink/40 bg-paper px-4 py-3 text-sm italic">
                <span className="sr-only">Example: </span>
                {example}
              </p>
              <p className="mt-4 border-t-2 border-ink pt-4 font-semibold">
                <span className="text-accent">Remember:</span> {remember}
              </p>
            </Card>
          ))}
        </ul>
      </Container>
    </section>
  );
}

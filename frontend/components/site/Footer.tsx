import Link from "next/link";
import { PhoneCall } from "lucide-react";
import { Container } from "@/components/ui/Container";
import { GITHUB_URL, NAV_LINKS } from "@/lib/site";
import { Logo } from "./Logo";

export function Footer() {
  return (
    <footer className="mt-auto border-t-2 border-ink bg-card">
      <Container className="grid gap-10 py-12 md:grid-cols-[1fr_auto] md:gap-16">
        <div className="max-w-md">
          <Logo />
          <p className="mt-3 text-ink-muted">
            Helping Indian families spot UPI and link scams before any money moves.
          </p>
          <nav aria-label="Footer" className="mt-6">
            <ul className="flex flex-wrap gap-x-6 gap-y-2 font-semibold">
              {NAV_LINKS.map((l) => (
                <li key={l.href}>
                  <Link href={l.href} className="underline-offset-4 hover:underline">
                    {l.label}
                  </Link>
                </li>
              ))}
              <li>
                <a
                  href={GITHUB_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline-offset-4 hover:underline"
                >
                  GitHub<span className="sr-only"> (opens in a new tab)</span>
                </a>
              </li>
            </ul>
          </nav>
        </div>

        <aside
          aria-labelledby="help-title"
          className="rounded-2xl border-2 border-ink bg-scam-tint p-5 shadow-brutal md:max-w-sm"
        >
          <h2
            id="help-title"
            className="flex items-center gap-2 font-display text-xl font-extrabold"
          >
            <PhoneCall aria-hidden className="size-5 text-scam-deep" />
            Already lost money?
          </h2>
          <p className="mt-2">
            Call{" "}
            <a
              href="tel:1930"
              className="font-extrabold text-scam-deep underline underline-offset-4"
            >
              1930
            </a>{" "}
            immediately or report at{" "}
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="font-bold text-scam-deep underline underline-offset-4"
            >
              cybercrime.gov.in
            </a>
            .
          </p>
          <p lang="hi" className="mt-2 text-ink-muted">
            पैसे कट गए? तुरंत 1930 पर कॉल करें।
          </p>
        </aside>
      </Container>
      <div className="border-t-2 border-ink">
        <Container className="flex flex-col gap-1 py-4 text-sm text-ink-muted sm:flex-row sm:justify-between">
          <p>Built by Anurag</p>
          <p>Kavach gives guidance, not guarantees. When in doubt, don&apos;t pay.</p>
        </Container>
      </div>
    </footer>
  );
}

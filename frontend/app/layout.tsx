import type { Metadata, Viewport } from "next";
import { Bricolage_Grotesque, Inter, Noto_Sans_Devanagari } from "next/font/google";
import { SITE_URL } from "@/lib/site";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const bricolage = Bricolage_Grotesque({
  variable: "--font-bricolage",
  subsets: ["latin"],
  display: "swap",
});

// Only used for short Hindi snippets, so it isn't preloaded.
const devanagari = Noto_Sans_Devanagari({
  variable: "--font-devanagari",
  subsets: ["devanagari"],
  display: "swap",
  preload: false,
});

const title = "Kavach — Check a message before you pay";
const description =
  "Paste any SMS, WhatsApp message, link, UPI ID or QR code. Kavach tells you in seconds if it's a scam — and exactly why — in English and Hindi.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: title, template: "%s · Kavach" },
  description,
  applicationName: "Kavach",
  openGraph: {
    type: "website",
    siteName: "Kavach",
    title,
    description,
    locale: "en_IN",
    url: "/",
  },
  twitter: { card: "summary_large_image", title, description },
};

export const viewport: Viewport = {
  themeColor: "#FBF8F1",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      data-scroll-behavior="smooth"
      className={`${inter.variable} ${bricolage.variable} ${devanagari.variable} antialiased`}
    >
      <body className="flex min-h-dvh flex-col">
        <a
          href="#main"
          className="sr-only z-100 rounded-xl border-2 border-ink bg-card px-4 py-2 font-bold shadow-brutal focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
        >
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}

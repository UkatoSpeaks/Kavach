/** Site-wide constants shared by the navbar, footer and metadata. */

export const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";

export const GITHUB_URL = "https://github.com/UkatoSpeaks/Kavach";

export const NAV_LINKS = [
  { href: "/check", label: "Check" },
  { href: "/#how", label: "How it works" },
  { href: "/#scams", label: "Scams" },
] as const;

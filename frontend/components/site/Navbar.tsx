"use client";

import { AnimatePresence, MotionConfig, motion } from "motion/react";
import Link from "next/link";
import { useEffect, useId, useState } from "react";
import { Menu, X } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { GITHUB_URL, NAV_LINKS } from "@/lib/site";
import { GitHubIcon } from "./GitHubIcon";
import { Logo } from "./Logo";

const linkClass =
  "rounded-lg px-3 py-2 font-semibold text-ink transition-colors hover:bg-accent-tint hover:text-accent-dark";

/** Floating pill navbar; collapses to a menu below the md breakpoint. */
export function Navbar() {
  const [open, setOpen] = useState(false);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const [check, ...rest] = NAV_LINKS;

  return (
    <header className="sticky top-0 z-50 px-3 pt-3 sm:px-6 sm:pt-4">
      <nav
        aria-label="Main"
        className="mx-auto flex max-w-5xl items-center justify-between gap-3 rounded-full border-2 border-ink bg-card py-2 pr-2 pl-4 shadow-brutal"
      >
        <Logo />

        {/* Desktop links */}
        <ul className="hidden items-center gap-1 md:flex">
          {rest.map((l) => (
            <li key={l.href}>
              <Link href={l.href} className={linkClass}>
                {l.label}
              </Link>
            </li>
          ))}
          <li>
            <a
              href={GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={`${linkClass} inline-flex items-center`}
              aria-label="Kavach on GitHub (opens in a new tab)"
            >
              <GitHubIcon className="size-5" />
            </a>
          </li>
          <li className="ml-1">
            <Button href={check.href} size="sm" className="rounded-full">
              {check.label}
            </Button>
          </li>
        </ul>

        {/* Mobile toggle */}
        <button
          type="button"
          className="inline-flex size-11 items-center justify-center rounded-full border-2 border-ink bg-paper md:hidden"
          aria-expanded={open}
          aria-controls={menuId}
          aria-label={open ? "Close menu" : "Open menu"}
          onClick={() => setOpen((o) => !o)}
        >
          {open ? <X aria-hidden className="size-5" /> : <Menu aria-hidden className="size-5" />}
        </button>
      </nav>

      <MotionConfig reducedMotion="user">
        <AnimatePresence>
          {open && (
            <motion.div
              id={menuId}
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.15 }}
              className="mx-auto mt-2 max-w-5xl rounded-2xl border-2 border-ink bg-card p-2 shadow-brutal md:hidden"
            >
              <ul className="flex flex-col">
                {NAV_LINKS.map((l) => (
                  <li key={l.href}>
                    <Link
                      href={l.href}
                      className={`${linkClass} block py-3 text-lg`}
                      onClick={() => setOpen(false)}
                    >
                      {l.label}
                    </Link>
                  </li>
                ))}
                <li>
                  <a
                    href={GITHUB_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`${linkClass} flex items-center gap-2 py-3 text-lg`}
                  >
                    <GitHubIcon className="size-5" />
                    GitHub
                    <span className="sr-only">(opens in a new tab)</span>
                  </a>
                </li>
              </ul>
            </motion.div>
          )}
        </AnimatePresence>
      </MotionConfig>
    </header>
  );
}

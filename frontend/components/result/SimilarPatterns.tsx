import { useId } from "react";
import { ExternalLink } from "lucide-react";
import type { SimilarPattern } from "@/lib/types";
import { SectionTitle } from "./SectionTitle";

const chip =
  "inline-flex min-h-10 items-center gap-1.5 rounded-full border-2 border-ink bg-card px-3 py-1 text-sm font-semibold";

/** Known scams from the knowledge base that this one resembles. */
export function SimilarPatterns({ patterns }: { patterns: SimilarPattern[] }) {
  const id = useId();
  if (patterns.length === 0) return null;

  return (
    <section aria-labelledby={`${id}-title`}>
      <SectionTitle id={`${id}-title`}>Similar known scams</SectionTitle>
      <ul className="mt-3 flex flex-wrap gap-2">
        {patterns.map((p) => (
          <li key={p.slug}>
            {p.source_url ? (
              <a
                href={p.source_url}
                target="_blank"
                rel="noopener noreferrer"
                className={`${chip} hover:bg-accent-tint`}
              >
                {p.title}
                <ExternalLink aria-hidden className="size-3.5" />
                <span className="sr-only">(source, opens in a new tab)</span>
              </a>
            ) : (
              <span className={chip}>{p.title}</span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

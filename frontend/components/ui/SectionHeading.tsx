import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

type SectionHeadingProps = {
  id?: string;
  eyebrow?: string;
  title: ReactNode;
  intro?: ReactNode;
  align?: "left" | "center";
  className?: string;
};

/** Eyebrow + h2 + intro paragraph, used at the top of every landing section. */
export function SectionHeading({
  id,
  eyebrow,
  title,
  intro,
  align = "left",
  className,
}: SectionHeadingProps) {
  return (
    <div className={cn("max-w-2xl", align === "center" && "mx-auto text-center", className)}>
      {eyebrow && (
        <p className="mb-2 text-sm font-bold tracking-widest text-accent uppercase">{eyebrow}</p>
      )}
      <h2
        id={id}
        className="font-display text-3xl leading-tight font-extrabold tracking-tight text-balance sm:text-4xl"
      >
        {title}
      </h2>
      {intro && <p className="mt-3 text-lg text-ink-muted text-pretty">{intro}</p>}
    </div>
  );
}

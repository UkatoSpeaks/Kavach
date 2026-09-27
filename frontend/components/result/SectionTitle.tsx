import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

/** Small heading for a block inside the result panel. */
export function SectionTitle({
  id,
  children,
  className,
}: {
  id?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <h3 id={id} className={cn("font-display text-xl font-extrabold tracking-tight", className)}>
      {children}
    </h3>
  );
}

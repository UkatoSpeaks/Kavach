import type { ComponentPropsWithoutRef, ElementType } from "react";
import { cn } from "@/lib/cn";

type ContainerProps<T extends ElementType> = { as?: T } & ComponentPropsWithoutRef<T>;

/** Centred page-width wrapper with a 16px gutter on phones. */
export function Container<T extends ElementType = "div">({
  as,
  className,
  ...props
}: ContainerProps<T>) {
  const Tag = as ?? "div";
  return <Tag className={cn("mx-auto w-full max-w-6xl px-4 sm:px-6 lg:px-8", className)} {...props} />;
}

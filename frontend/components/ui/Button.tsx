import Link from "next/link";
import type { ComponentPropsWithoutRef, ReactNode } from "react";
import { cn } from "@/lib/cn";

const variants = {
  primary: "bg-accent text-white hover:bg-accent-dark",
  secondary: "bg-card text-ink hover:bg-accent-tint",
  ink: "bg-ink text-paper hover:bg-ink/90",
};

const sizes = {
  md: "min-h-12 px-5 text-base",
  lg: "min-h-14 px-6 text-lg",
  sm: "min-h-10 px-4 text-sm",
};

type BaseProps = {
  variant?: keyof typeof variants;
  size?: keyof typeof sizes;
  icon?: ReactNode;
  className?: string;
  children: ReactNode;
};

type ButtonAsLink = BaseProps & { href: string } & Omit<ComponentPropsWithoutRef<typeof Link>, "className" | "children">;
type ButtonAsButton = BaseProps & { href?: undefined } & Omit<ComponentPropsWithoutRef<"button">, "className" | "children">;

/**
 * Bordered button with a hard shadow that presses down on click.
 * Renders a Next.js <Link> when `href` is given, otherwise a <button>.
 */
export function Button(props: ButtonAsLink | ButtonAsButton) {
  const { variant = "primary", size = "md", icon, className, children } = props;
  const classes = cn(
    "inline-flex items-center justify-center gap-2 rounded-xl border-2 border-ink font-bold",
    "shadow-brutal transition-[transform,box-shadow,background-color] duration-100 ease-out",
    "hover:-translate-x-px hover:-translate-y-px hover:shadow-brutal-lg",
    "active:translate-x-1 active:translate-y-1 active:shadow-none",
    "disabled:pointer-events-none disabled:opacity-60",
    variants[variant],
    sizes[size],
    className,
  );
  const content = (
    <>
      {children}
      {icon}
    </>
  );

  if (props.href !== undefined) {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { variant: _v, size: _s, icon: _i, className: _c, children: _ch, ...rest } = props;
    return (
      <Link className={classes} {...rest}>
        {content}
      </Link>
    );
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { variant: _v, size: _s, icon: _i, className: _c, children: _ch, ...rest } = props;
  return (
    <button type="button" className={classes} {...rest}>
      {content}
    </button>
  );
}

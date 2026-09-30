"use client";

import { useEffect, useState } from "react";
import { AlertCircle, MessageSquareText, RotateCcw } from "lucide-react";
import type { FriendlyError } from "@/lib/errors";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";

type ErrorNoticeProps = {
  error: FriendlyError;
  onRetry?: () => void;
  /** Shown as "Use the Message tab" (when a screenshot couldn't be read). */
  onUseMessageTab?: () => void;
};

/** A friendly error with a retry button; for 429s the button unlocks after a countdown. */
export function ErrorNotice({ error, onRetry, onUseMessageTab }: ErrorNoticeProps) {
  const [left, setLeft] = useState(error.retryAfter ?? 0);

  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => setLeft((n) => n - 1), 1000);
    return () => clearTimeout(t);
  }, [left]);

  const title =
    error.retryAfter && left > 0
      ? `Too many checks — try again in ${left} second${left === 1 ? "" : "s"}.`
      : error.retryAfter
        ? "You can check again now."
        : error.title;

  return (
    <Card role="alert" className="p-5 sm:p-6">
      <div className="flex gap-3">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-xl border-2 border-ink bg-accent-tint text-accent-dark">
          <AlertCircle aria-hidden className="size-5" />
        </span>
        <div className="min-w-0">
          <p className="font-display text-xl font-extrabold">{title}</p>
          {error.detail && <p className="mt-1 text-ink-muted">{error.detail}</p>}
          {((error.canRetry && onRetry) || onUseMessageTab) && (
            <div className="mt-4 flex flex-wrap gap-3">
              {error.canRetry && onRetry && (
                <Button
                  size="sm"
                  onClick={onRetry}
                  disabled={left > 0}
                  icon={<RotateCcw aria-hidden className="order-first size-4" />}
                >
                  {left > 0 ? `Retry in ${left}s` : "Try again"}
                </Button>
              )}
              {onUseMessageTab && (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={onUseMessageTab}
                  icon={<MessageSquareText aria-hidden className="order-first size-4" />}
                >
                  Use the Message tab
                </Button>
              )}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}

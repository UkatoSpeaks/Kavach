"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowRight, SearchX } from "lucide-react";
import { getAnalysis } from "@/lib/api";
import { friendlyError, type FriendlyError } from "@/lib/errors";
import type { AnalysisResult } from "@/lib/types";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { ErrorNotice } from "@/components/check/ErrorNotice";
import { LoadingCard } from "@/components/check/LoadingCard";
import { ResultPanel } from "./ResultPanel";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SLOW_AFTER_MS = 6000;

type State =
  | { state: "loading"; slow: boolean }
  | { state: "done"; result: AnalysisResult }
  | { state: "not_found" }
  | { state: "error"; error: FriendlyError; attempt: number };

function CheckYourOwn() {
  return (
    <Button href="/check" size="lg" icon={<ArrowRight aria-hidden className="size-5" />}>
      Check your own message
    </Button>
  );
}

/** GET /analysis/{id} rendered read-only, with a call to check your own message. */
export function SharedResult({ id }: { id: string }) {
  const valid = UUID.test(id);
  const [state, setState] = useState<State>(
    valid ? { state: "loading", slow: false } : { state: "not_found" },
  );
  const attempts = useRef(0);

  const load = useCallback(
    (signal: AbortSignal) => {
      setState({ state: "loading", slow: false });
      const slow = setTimeout(
        () => setState((s) => (s.state === "loading" ? { state: "loading", slow: true } : s)),
        SLOW_AFTER_MS,
      );
      getAnalysis(id, { signal })
        .then((result) => setState({ state: "done", result }))
        .catch((err) => {
          if (signal.aborted) return;
          const error = friendlyError(err, "load");
          if (error.canRetry) {
            attempts.current += 1;
            setState({ state: "error", error, attempt: attempts.current });
          } else {
            setState({ state: "not_found" });
          }
        })
        .finally(() => clearTimeout(slow));
    },
    [id],
  );

  useEffect(() => {
    if (!valid) return;
    const ctrl = new AbortController();
    // Fetch-on-mount: the result lives on the API, not in this app.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load(ctrl.signal);
    return () => ctrl.abort();
  }, [valid, load]);

  if (state.state === "not_found") {
    return (
      <Card className="p-6 text-center sm:p-10">
        <span className="mx-auto flex size-14 items-center justify-center rounded-xl border-2 border-ink bg-accent-tint text-accent-dark">
          <SearchX aria-hidden className="size-7" />
        </span>
        <h1 className="mt-5 font-display text-3xl font-extrabold sm:text-4xl">
          This result isn&apos;t available
        </h1>
        <p className="mx-auto mt-3 max-w-md text-lg text-ink-muted">
          The link may be incomplete, or the result was never saved. You can check the message
          yourself — it takes a few seconds.
        </p>
        <div className="mt-8">
          <CheckYourOwn />
        </div>
      </Card>
    );
  }

  return (
    <>
      <h1 className="font-display text-3xl leading-tight font-extrabold tracking-tight sm:text-4xl">
        Someone checked a message with Kavach
      </h1>
      <p className="mt-2 text-lg text-ink-muted">
        Here&apos;s what we found. The original message isn&apos;t shown on shared links, to
        protect the privacy of the person who checked it.
      </p>
      <div className="mt-6">
        {state.state === "loading" && <LoadingCard slow={state.slow} />}
        {state.state === "error" && (
          <ErrorNotice
            key={state.attempt}
            error={state.error}
            onRetry={() => load(new AbortController().signal)}
          />
        )}
        {state.state === "done" && (
          <ResultPanel result={state.result} source={{ kind: "none" }} readOnly />
        )}
      </div>
      <Card tone="accent" className="mt-8 flex flex-col items-start gap-4 p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6">
        <p className="font-display text-xl font-extrabold">Got a suspicious message yourself?</p>
        <CheckYourOwn />
      </Card>
    </>
  );
}

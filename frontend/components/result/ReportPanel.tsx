"use client";

import { useId, useState } from "react";
import { Check, Flag, Loader2 } from "lucide-react";
import { reportEntity } from "@/lib/api";
import { friendlyError } from "@/lib/errors";
import { ENTITY_LABEL } from "@/lib/labels";
import type { AnalysisResult, ReportableEntity } from "@/lib/types";
import { Button } from "@/components/ui/Button";

type Status =
  | { state: "idle" }
  | { state: "sending" }
  | { state: "done"; count: number }
  | { state: "error"; message: string };

const key = (e: ReportableEntity) => `${e.entity_type}:${e.value}`;

/** Report the input's UPI IDs, phone numbers and websites to the community list. */
export function ReportPanel({ result }: { result: AnalysisResult }) {
  const id = useId();
  const entities = result.entities ?? [];
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [status, setStatus] = useState<Record<string, Status>>({});
  const [sending, setSending] = useState(false);

  const toggle = (k: string) =>
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  async function submit() {
    setSending(true);
    for (const entity of entities) {
      const k = key(entity);
      if (!selected.has(k) || status[k]?.state === "done") continue;
      setStatus((s) => ({ ...s, [k]: { state: "sending" } }));
      try {
        const res = await reportEntity({
          ...entity,
          reason: result.scam_type ? `kavach: ${result.scam_type}` : "kavach",
          analysis_id: result.id,
        });
        setStatus((s) => ({ ...s, [k]: { state: "done", count: res.report_count } }));
      } catch (err) {
        const { title } = friendlyError(err, "report");
        setStatus((s) => ({ ...s, [k]: { state: "error", message: title } }));
      }
    }
    setSending(false);
  }

  const pending = entities.filter(
    (e) => selected.has(key(e)) && status[key(e)]?.state !== "done",
  ).length;

  return (
    <div className="rounded-xl border-2 border-ink bg-paper p-4">
      <p id={`${id}-label`} className="font-bold">
        Which of these did the scammer use?
      </p>
      <p className="text-sm text-ink-muted">
        Only pick the scammer&apos;s details — never a real bank or company website. Reports help
        warn others who get the same message.
      </p>
      <ul aria-labelledby={`${id}-label`} className="mt-3 flex flex-col gap-2">
        {entities.map((e) => {
          const k = key(e);
          const st = status[k] ?? { state: "idle" };
          const done = st.state === "done";
          return (
            <li key={k}>
              <label className="flex min-h-11 cursor-pointer items-center gap-3 rounded-lg border-2 border-ink bg-card px-3 py-2 has-[:focus-visible]:outline-3 has-[:focus-visible]:outline-accent">
                <input
                  type="checkbox"
                  className="size-5 shrink-0 accent-accent"
                  checked={selected.has(k) || done}
                  disabled={done || sending}
                  onChange={() => toggle(k)}
                />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-semibold text-ink-muted">
                    {ENTITY_LABEL[e.entity_type]}
                  </span>
                  <span className="block font-mono text-sm [overflow-wrap:anywhere]">{e.value}</span>
                  <span className="block text-sm font-semibold" aria-live="polite">
                    {st.state === "sending" && (
                      <span className="inline-flex items-center gap-1 text-ink-muted">
                        <Loader2 aria-hidden className="size-4 animate-spin" />
                        Sending…
                      </span>
                    )}
                    {done && (
                      <span className="inline-flex items-center gap-1 text-accent-dark">
                        <Check aria-hidden className="size-4" />
                        Reported
                        {st.count > 1 && ` · ${st.count} reports so far`}
                      </span>
                    )}
                    {st.state === "error" && <span className="text-ink">{st.message}</span>}
                  </span>
                </span>
              </label>
            </li>
          );
        })}
      </ul>
      <Button
        className="mt-3 w-full sm:w-auto"
        size="sm"
        variant="ink"
        disabled={pending === 0 || sending}
        onClick={submit}
        icon={
          sending ? (
            <Loader2 aria-hidden className="size-4 animate-spin" />
          ) : (
            <Flag aria-hidden className="size-4" />
          )
        }
      >
        {sending ? "Reporting…" : pending > 1 ? `Report ${pending} items` : "Report"}
      </Button>
    </div>
  );
}

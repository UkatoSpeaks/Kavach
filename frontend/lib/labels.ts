/** Plain-language names for the API's machine values. */

import type { EntityType, RedFlag, ScamType, Signal, Verdict } from "./types";

export const VERDICT_LABEL: Record<Verdict, string> = {
  safe: "SAFE",
  suspicious: "SUSPICIOUS",
  scam: "SCAM",
};

export const VERDICT_SUMMARY: Record<Verdict, string> = {
  safe: "No warning signs found",
  suspicious: "Be careful — some warning signs",
  scam: "This looks like a scam",
};

const SCAM_TYPE_LABEL: Record<ScamType, string> = {
  upi_receive_money: "Fake “receive money” request — you never need a PIN to receive money",
  qr_code: "QR code trick — scanning a QR code only ever sends money",
  sent_by_mistake: "“Sent by mistake” refund trick",
  phishing_link: "Fake link or notice (phishing)",
  task_job: "Task-based job scam",
  fake_customer_care: "Fake customer care",
  generic: "Common scam warning signs",
};

export function scamTypeLabel(type: string | null): string | null {
  if (!type) return null;
  return SCAM_TYPE_LABEL[type as ScamType] ?? type.replaceAll("_", " ");
}

const SIGNAL_LABEL: Record<string, string> = {
  rules: "Scam-pattern rules",
  classifier: "Scam classifier",
  url_intel: "Link check",
  upi_check: "UPI ID check",
  reputation: "Community reports",
  pattern_similarity: "Pattern match",
  llm: "AI review",
};

export function signalLabel(source: string): string {
  return SIGNAL_LABEL[source] ?? source.replaceAll("_", " ");
}

export type SignalStatus = "counted" | "not_counted" | "unavailable";

/**
 * - `unavailable`: the check failed or is switched off (the API reports score 0; that is
 *   not a real zero and must never be shown as one).
 * - `not_counted`: it ran but found nothing either way, or was overruled (weight 0).
 */
export function signalStatus(s: Signal): SignalStatus {
  if (s.detail.startsWith("unavailable")) return "unavailable";
  return s.weight > 0 ? "counted" : "not_counted";
}

/** A short reason for an unavailable signal, without model names or exception classes. */
export function unavailableReason(s: Signal): string {
  const detail = s.detail.replace(/^unavailable:?\s*/, "");
  if (s.source === "llm") {
    if (/not configured|no api key/i.test(detail)) return "Switched off on this server.";
    return "The AI reviewer couldn't be reached, so standard explanations were used.";
  }
  if (/not configured|disabled|offline/i.test(detail)) return "Switched off on this server.";
  if (/timed out/i.test(detail)) return "Took too long, so it was skipped.";
  if (!detail) return "Not available for this check.";
  return "Couldn't run this time, so it was skipped.";
}

export const ENTITY_LABEL: Record<EntityType, string> = {
  upi: "UPI ID",
  phone: "Phone number",
  domain: "Website",
  url: "Link",
};

export const SEVERITY_LABEL = { low: "Minor sign", medium: "Warning sign", high: "Strong sign" };

/** A one-line, plain-language version of a signal's (technical) detail. */
export function signalSummary(s: Signal, flags: RedFlag[]): string {
  const d = s.detail;
  switch (s.source) {
    case "rules": {
      const n = /^(\d+) rule/.exec(d)?.[1];
      if (n) return `${n} scam warning sign${n === "1" ? "" : "s"} in the wording.`;
      if (d.includes("no message text")) return "Only reads messages, so it doesn't count here.";
      return "No scam wording found.";
    }
    case "url_intel":
      if (d.startsWith("no issues found")) return "No problems found with the link.";
      return withFlagMessages(d, flags);
    case "upi_check":
      if (d.startsWith("no issues found")) return "No problems found with the UPI ID.";
      return withFlagMessages(d, flags);
    case "reputation":
      if (d.startsWith("no community reports")) return "No one has reported these yet.";
      return d;
    case "pattern_similarity":
      if (d.startsWith("skipped")) return "Message too short to compare reliably.";
      if (s.weight > 0) return "Reads like a known scam from our knowledge base.";
      return "Not clearly closer to a known scam than to a genuine message.";
    case "llm":
      if (d.includes("manipulate")) return "The message tries to fool AI checkers, so this was ignored.";
      if (d.includes("disagrees")) return "Disagreed strongly with the other checks, so it was left out.";
      return `An AI model read the message and rated the risk ${Math.round(s.score)}/100.`;
    default:
      return withFlagMessages(d, flags);
  }
}

/** Replace red-flag codes (snake_case) in a detail string with their messages. */
function withFlagMessages(detail: string, flags: RedFlag[]): string {
  const byCode = new Map(flags.map((f) => [f.code, f.message]));
  const text = detail.replace(/\b[a-z0-9]+(?:_[a-z0-9]+)+\b/g, (code) => byCode.get(code) ?? code);
  return text.charAt(0).toUpperCase() + text.slice(1);
}

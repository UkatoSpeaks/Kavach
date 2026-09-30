/** Turn API errors into plain, friendly words. Never shows raw JSON or status codes. */

import { ApiError } from "./api";

export type ErrorContext = "text" | "url" | "upi" | "qr" | "screenshot" | "load" | "report";

export type FriendlyError = {
  title: string;
  detail?: string;
  /** Seconds until retrying makes sense (429). */
  retryAfter?: number;
  /** false when retrying the same input can't help (fix the input instead). */
  canRetry: boolean;
  /** Offer a button that switches to the Message tab (the screenshot couldn't be read). */
  suggestMessageTab?: boolean;
};

const INVALID: Record<ErrorContext, string> = {
  text: "Please paste a message of up to 5,000 characters.",
  url: "Enter just one link, like example.com/page — without any other text.",
  upi: "Enter a UPI ID like name@okaxis, or a upi://pay link.",
  qr: "That image couldn't be read. Try a PNG or JPG photo of the QR code.",
  screenshot: "That image couldn't be read. Try a PNG, JPG or WEBP screenshot.",
  load: "That result link isn't valid.",
  report: "That can't be reported.",
};

export function friendlyError(err: unknown, context: ErrorContext): FriendlyError {
  if (!(err instanceof ApiError)) {
    return { title: "Something went wrong.", detail: "Please try again.", canRetry: true };
  }
  switch (err.kind) {
    case "aborted":
      return { title: "Check cancelled.", canRetry: true };
    case "timeout":
      return {
        title: "The server is taking too long.",
        detail: "It may still be waking up. Please try again — the next try is usually quick.",
        canRetry: true,
      };
    case "network":
      return {
        title: "Couldn't reach Kavach.",
        detail: "Check your internet connection and try again.",
        canRetry: true,
      };
  }

  const status = err.status ?? 0;
  if (status === 429) {
    const n = err.retryAfter;
    return {
      title: n
        ? `Too many checks — try again in ${n} second${n === 1 ? "" : "s"}.`
        : "Too many checks — please wait a minute and try again.",
      detail: "There's a limit per person to keep this free service running for everyone.",
      retryAfter: n ?? 60,
      canRetry: true,
    };
  }
  if (err.code === "no_qr_code") {
    return {
      title: "We couldn't find a QR code in that image.",
      detail: "Try a sharper, closer photo with the whole QR code visible, or a screenshot of it.",
      canRetry: false,
    };
  }
  if (err.code === "ocr_unavailable") {
    return {
      title: "We couldn't read the screenshot right now (our free image reader is busy).",
      detail: "Please try again in a minute, or copy the message text into the Message tab.",
      canRetry: true,
      suggestMessageTab: true,
    };
  }
  if (err.code === "no_text_found") {
    return {
      title: "We couldn't find any text in this image.",
      detail: "Try a clearer or uncropped screenshot.",
      canRetry: false,
    };
  }
  const image = context === "qr" || context === "screenshot";
  if (status === 413) {
    return {
      title: image ? "That image is too big." : "That's too long to check.",
      detail:
        context === "qr"
          ? "Images must be under 5 MB. Try a screenshot, or crop the photo to the QR code."
          : context === "screenshot"
            ? "Screenshots must be under 5 MB. Try a normal phone screenshot rather than a photo, or crop it to the message."
            : "Messages can be up to 5,000 characters. Paste just the suspicious part.",
      canRetry: false,
    };
  }
  // The API sent 422 for unsupported screenshots before it switched to 415: match the code.
  if (status === 415 || err.code === "unsupported_image") {
    return {
      title: "That file type isn't supported.",
      detail:
        context === "screenshot"
          ? "Please use a PNG, JPG or WEBP image of up to 5 MB."
          : "Please use a PNG or JPG image of up to 5 MB.",
      canRetry: false,
    };
  }
  if (status === 404) {
    return context === "load"
      ? {
          title: "This result isn't available.",
          detail: "The link may be wrong, or the result was never saved.",
          canRetry: false,
        }
      : { title: "Not found.", detail: "Please check again from the start.", canRetry: false };
  }
  if (status === 422 || status === 400) {
    return { title: "That doesn't look right.", detail: INVALID[context], canRetry: false };
  }
  if (status >= 500) {
    return {
      title: "Something went wrong on our side.",
      detail: "Please try again in a minute.",
      canRetry: true,
    };
  }
  return { title: "Something went wrong.", detail: "Please try again.", canRetry: true };
}

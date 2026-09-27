/**
 * Client for the Kavach FastAPI backend (types in lib/types.ts).
 *
 * The browser calls the API directly, never through a Next.js proxy: rate limits are per
 * client IP, and a proxy would make every visitor share the server's IP. The API must list
 * this site's origin in CORS_ORIGINS.
 */

import type {
  AnalysisResult,
  AnalyzeQuery,
  AnalyzeTextRequest,
  AnalyzeUpiRequest,
  AnalyzeUrlRequest,
  ApiErrorBody,
  ReportRequest,
  ReportResponse,
} from "./types";

export const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "https://kavach-api-mib4.onrender.com"
).replace(/\/+$/, "");

/** A free Render server can take close to a minute to wake up; give up after this. */
export const REQUEST_TIMEOUT_MS = 75_000;

let warmedUp = false;

/**
 * Wake the free Render server (it sleeps when idle) while the user reads the page.
 * Fire-and-forget: one request per page load, never throws, never shows an error.
 * `no-cors` means the request is sent without needing CORS headers; we ignore the response.
 */
export function warmUp(): void {
  if (warmedUp || typeof window === "undefined") return;
  warmedUp = true;
  fetch(`${API_URL}/health`, { mode: "no-cors", cache: "no-store", keepalive: true }).catch(
    () => {},
  );
}

// ---------------------------------------------------------------- errors

/**
 * - `http`: the API answered with an error status (see `status`, `code`).
 * - `network`: no answer at all: offline, DNS, server down, or blocked by CORS
 *   (browsers don't tell these apart).
 * - `timeout`: no answer within the timeout.
 * - `aborted`: cancelled by the caller.
 */
export type ApiErrorKind = "http" | "network" | "timeout" | "aborted";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status?: number;
  readonly code?: string;
  /** Seconds, from the Retry-After header (429). */
  readonly retryAfter?: number;

  constructor(
    kind: ApiErrorKind,
    message: string,
    init: { status?: number; code?: string; retryAfter?: number } = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = init.status;
    this.code = init.code;
    this.retryAfter = init.retryAfter;
  }
}

type RequestOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
};

async function request<T>(
  path: string,
  init: RequestInit,
  { signal, timeoutMs = REQUEST_TIMEOUT_MS }: RequestOptions = {},
): Promise<T> {
  // One controller for both the caller's cancel and our timeout (AbortSignal.any is too new
  // for some phones still in use).
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const onAbort = () => controller.abort();
  if (signal?.aborted) controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    let res: Response;
    try {
      res = await fetch(`${API_URL}${path}`, {
        ...init,
        signal: controller.signal,
        cache: "no-store",
      });
    } catch {
      if (timedOut) throw new ApiError("timeout", "The server took too long to answer.");
      if (signal?.aborted) throw new ApiError("aborted", "Cancelled.");
      throw new ApiError("network", "Could not reach the server.");
    }

    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as ApiErrorBody | null;
      const retry = Number.parseInt(res.headers.get("Retry-After") ?? "", 10);
      throw new ApiError("http", body?.error?.message ?? `HTTP ${res.status}`, {
        status: res.status,
        code: body?.error?.code,
        retryAfter: Number.isFinite(retry) ? retry : undefined,
      });
    }
    try {
      return (await res.json()) as T;
    } catch {
      if (timedOut) throw new ApiError("timeout", "The server took too long to answer.");
      if (signal?.aborted) throw new ApiError("aborted", "Cancelled.");
      throw new ApiError("network", "The answer was cut off.");
    }
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

function postJson<T>(path: string, body: unknown, options?: RequestOptions): Promise<T> {
  return request<T>(
    path,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
    options,
  );
}

function withQuery(path: string, query?: AnalyzeQuery): string {
  return query?.explain === false ? `${path}?explain=false` : path;
}

// ---------------------------------------------------------------- endpoints

export type AnalyzeOptions = RequestOptions & AnalyzeQuery;

export function analyzeText(body: AnalyzeTextRequest, options: AnalyzeOptions = {}) {
  return postJson<AnalysisResult>(withQuery("/analyze/text", options), body, options);
}

export function analyzeUrl(body: AnalyzeUrlRequest, options: AnalyzeOptions = {}) {
  return postJson<AnalysisResult>(withQuery("/analyze/url", options), body, options);
}

export function analyzeUpi(body: AnalyzeUpiRequest, options: AnalyzeOptions = {}) {
  return postJson<AnalysisResult>(withQuery("/analyze/upi", options), body, options);
}

/** PNG or JPEG, max 5 MB. 422 `no_qr_code` when the image has no readable QR code. */
export function analyzeQr(image: Blob, options: AnalyzeOptions = {}) {
  const form = new FormData();
  form.append("image", image, image instanceof File ? image.name : "qr.png");
  // No Content-Type header: the browser sets the multipart boundary.
  return request<AnalysisResult>(
    withQuery("/analyze/qr", options),
    { method: "POST", body: form },
    options,
  );
}

/** A saved analysis. 404 if it doesn't exist (or its background save failed). */
export function getAnalysis(id: string, options: RequestOptions = {}) {
  return request<AnalysisResult>(
    `/analysis/${encodeURIComponent(id)}`,
    { method: "GET" },
    options,
  );
}

export function reportEntity(body: ReportRequest, options: RequestOptions = {}) {
  return postJson<ReportResponse>("/report", body, { timeoutMs: 30_000, ...options });
}

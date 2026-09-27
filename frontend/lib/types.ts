/**
 * Request and response shapes of the Kavach API. Mirrors the backend's Pydantic models:
 * backend/app/schemas/analysis.py, backend/app/schemas/entities.py,
 * backend/app/api/routes/analyze.py, backend/app/api/routes/report.py and
 * backend/app/api/errors.py. Keep in sync when those change.
 */

// ---------------------------------------------------------------- enums (app/core/enums.py)

export type Verdict = "safe" | "suspicious" | "scam";

export type Severity = "low" | "medium" | "high";

/** v1 scam types. `generic` covers signs (e.g. an OTP request) that fit any type. */
export type ScamType =
  | "upi_receive_money"
  | "qr_code"
  | "sent_by_mistake"
  | "phishing_link"
  | "task_job"
  | "fake_customer_care"
  | "generic";

export type EntityType = "upi" | "phone" | "url" | "domain";

export type Confidence = "low" | "medium" | "high";

/** Scoring layers that can appear in `signal_breakdown` (weights: SIGNAL_WEIGHTS). */
export type SignalSource =
  | "rules"
  | "classifier"
  | "url_intel"
  | "upi_check"
  | "reputation"
  | "pattern_similarity"
  | "llm";

// ---------------------------------------------------------------- AnalysisResult

/** A human-readable warning sign found in the input. */
export interface RedFlag {
  /** Stable machine id, e.g. "urgency". */
  code: string;
  message: string;
  /** The same in simple Hindi. */
  message_hi: string | null;
  severity: Severity;
  /**
   * The matched text or entity, taken from the *normalized* input (lower-cased, whitespace
   * collapsed). May join pieces with " … " or carry a note, e.g. "x.top (imitates 'sbi')".
   */
  evidence: string | null;
}

/** One scoring layer's contribution to the final risk score. */
export interface Signal {
  source: SignalSource | (string & {});
  /** 0-100. Unavailable signals report 0 with `detail` starting "unavailable". */
  score: number;
  /** 0-1, renormalized over the signals that counted. 0: not counted. */
  weight: number;
  detail: string;
}

/** A knowledge-base scam pattern retrieved via RAG. */
export interface SimilarPattern {
  slug: string;
  title: string;
  category: ScamType | null;
  /** Cosine similarity, 0-1. */
  similarity: number;
  source_url: string | null;
}

/** Something in the input a user can report with POST /report (value already normalized). */
export interface ReportableEntity {
  entity_type: EntityType;
  value: string;
}

export interface AnalysisResult {
  /** UUID. Set up front; the row is saved in the background. */
  id: string | null;
  /** ISO 8601. */
  created_at: string | null;
  /** 0-100. */
  risk_score: number;
  verdict: Verdict;
  /** null when the verdict is safe. */
  scam_type: ScamType | null;
  red_flags: RedFlag[];
  signal_breakdown: Signal[];
  explanation_en: string;
  explanation_hi: string;
  advice: string[];
  similar_patterns: SimilarPattern[];
  /** The LLM's confidence; "low" if it was overruled. null if no LLM was used. */
  confidence: Confidence | null;
  /** Optional: API versions deployed before this field existed don't send it. */
  entities?: ReportableEntity[];
}

// ---------------------------------------------------------------- requests

/** POST /analyze/text. `text`: 1-5000 characters, not blank. */
export interface AnalyzeTextRequest {
  text: string;
  /** "hi" returns advice in Hindi. Explanations are always both. */
  language_hint?: "en" | "hi" | "hinglish" | null;
}

/** POST /analyze/url. Exactly one URL and nothing else, max 2048 characters. */
export interface AnalyzeUrlRequest {
  url: string;
}

/** POST /analyze/upi. Exactly one of the two. */
export type AnalyzeUpiRequest =
  | { upi_id: string; upi_uri?: never }
  | { upi_uri: string; upi_id?: never };

/** POST /analyze/qr is multipart/form-data with one field, `image` (PNG or JPEG, max 5 MB). */

/** Query string accepted by every /analyze/* route. false: skip the LLM step. */
export interface AnalyzeQuery {
  explain?: boolean;
}

/** POST /report (201). */
export interface ReportRequest {
  entity_type: EntityType;
  /** 1-2048 characters; normalized by the server (422 if not a valid entity). */
  value: string;
  /** Max 1000 characters. */
  reason?: string | null;
  /** 404 if given and unknown. */
  analysis_id?: string | null;
}

export interface ReportResponse {
  /** The reported entity's id. */
  id: string;
  entity_type: EntityType;
  /** Normalized value. */
  value: string;
  report_count: number;
  is_verified_scam: boolean;
}

// ---------------------------------------------------------------- errors

/** Error codes the API sends (backend/app/api/errors.py plus route-specific ones). */
export type ApiErrorCode =
  | "bad_request"
  | "not_found"
  | "method_not_allowed"
  | "payload_too_large"
  | "unsupported_media_type"
  | "validation_error"
  | "rate_limited"
  | "internal_error"
  | "service_unavailable"
  | "image_too_large"
  | "unsupported_image"
  | "no_qr_code"
  | (string & {});

/** Every non-2xx response. 429s also carry a Retry-After header (seconds). */
export interface ApiErrorBody {
  error: {
    code: ApiErrorCode;
    message: string;
    /** Validation errors (422) only. */
    details?: { field: string; message: string }[];
  };
}

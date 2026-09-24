/** The three indicator kinds IOCLens knows how to classify and enrich. */
export type IndicatorType = "ip" | "domain" | "hash";

/** Hash algorithm inferred purely from string length/charset (no verification). */
export type HashAlgorithm = "md5" | "sha1" | "sha256";

export interface DetectedIndicator {
  /** The original input, unmodified. */
  raw: string;
  /** Normalized form used for lookups (lowercased domains, trimmed IPs). */
  value: string;
  type: IndicatorType;
  /** Only present when type === "ip". */
  ipVersion?: 4 | 6;
  /** Only present when type === "hash". */
  hashAlgorithm?: HashAlgorithm;
}

/** Status of a single OSINT source query within one enrichment run. */
export type SourceStatus = "ok" | "error" | "skipped";

export interface SourceResult<T> {
  /** Machine-readable source identifier, e.g. "crtsh", "rdap", "dns", "spamhaus-drop". */
  source: string;
  status: SourceStatus;
  /** Wall-clock time the query took, in milliseconds. Omitted when skipped. */
  durationMs?: number;
  /** Present when status === "error" or "skipped": a human-readable reason. */
  error?: string;
  /** Present when status === "ok": the parsed, source-specific data. */
  data?: T;
}

/** One scoring signal that contributed (or explicitly did not contribute) to the verdict. */
export interface Signal {
  /** Stable identifier, e.g. "domain-age-new". */
  id: string;
  /** Which source(s) this signal was derived from. */
  source: string;
  /** Points added to the risk score by this signal (0 if purely informational). */
  weight: number;
  /** Human-readable explanation of what was observed and why it scored the way it did. */
  description: string;
}

export type Verdict = "clean" | "low-risk" | "suspicious" | "high-risk" | "insufficient-data";

export interface EnrichmentResult {
  indicator: DetectedIndicator;
  verdict: Verdict;
  /** 0-100, clamped. Not meaningful (0) when verdict is "insufficient-data". */
  score: number;
  /** Ordered, human-readable explanation lines. Deterministically derived from `signals`. */
  reasoning: string[];
  signals: Signal[];
  sources: SourceResult<unknown>[];
  /** ISO-8601 timestamp of when the enrichment ran. */
  checkedAt: string;
}

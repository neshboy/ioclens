const CRT_SH_BASE = "https://crt.sh/";
const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_USER_AGENT = "ioclens/0.1 (+https://github.com/) - IOC enrichment engine, crt.sh domain lookup";

/** One raw certificate record as returned by crt.sh's JSON output mode. */
export interface CrtShCertificate {
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  id: number;
  entry_timestamp: string;
  not_before: string;
  not_after: string;
  serial_number: string;
}

/** Normalized summary IOCLens actually scores on, derived from the raw records. */
export interface CrtShSummary {
  domain: string;
  certificateCount: number;
  distinctIssuers: string[];
  /** ISO timestamp of the earliest `not_before` seen across all records, if any. */
  earliestIssuance?: string;
  /** ISO timestamp of the most recent `not_before` seen across all records, if any. */
  latestIssuance?: string;
}

export interface CrtShClientOptions {
  /** Injectable fetch implementation, primarily for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  userAgent?: string;
}

type ResolvedOptions = Required<CrtShClientOptions>;

function resolveOptions(options?: CrtShClientOptions): ResolvedOptions {
  return {
    fetchImpl: options?.fetchImpl ?? fetch,
    timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    userAgent: options?.userAgent ?? DEFAULT_USER_AGENT,
  };
}

async function fetchWithTimeout(url: string, opts: ResolvedOptions): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
  try {
    return await opts.fetchImpl(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": opts.userAgent,
        Accept: "application/json",
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Build the crt.sh JSON search URL for an exact domain name. */
export function buildCrtShUrl(domain: string): string {
  const params = new URLSearchParams({ q: domain, output: "json" });
  return `${CRT_SH_BASE}?${params.toString()}`;
}

/**
 * Query crt.sh for every logged certificate matching an exact domain name and
 * return the raw records. See `summarizeCertificates` to reduce this to the
 * fields IOCLens actually scores on.
 */
export async function queryDomain(domain: string, options?: CrtShClientOptions): Promise<CrtShCertificate[]> {
  const opts = resolveOptions(options);
  const url = buildCrtShUrl(domain);

  let response: Response;
  try {
    response = await fetchWithTimeout(url, opts);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`crt.sh request to ${url} failed: ${reason}`);
  }

  if (!response.ok) {
    throw new Error(`crt.sh request to ${url} returned HTTP ${response.status}`);
  }

  const text = await response.text();
  if (!text || !text.trim()) {
    // crt.sh returns an empty 200 body when a query matches nothing.
    return [];
  }

  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? (parsed as CrtShCertificate[]) : [];
  } catch {
    // crt.sh occasionally returns non-JSON (HTML error/interstitial pages)
    // when it's under heavy load. Surfaced as a distinct error so callers
    // (the enrichment orchestrator) can record it as a degraded source
    // rather than crash the whole check.
    throw new Error(`crt.sh returned a non-JSON response for domain "${domain}" (it may be overloaded - try again later)`);
  }
}

/** Reduce raw crt.sh records to the summary fields IOCLens scores on. */
export function summarizeCertificates(domain: string, records: CrtShCertificate[]): CrtShSummary {
  const issuers = new Set<string>();
  let earliest: string | undefined;
  let latest: string | undefined;

  for (const record of records) {
    if (record.issuer_name) issuers.add(record.issuer_name);
    if (record.not_before) {
      if (!earliest || record.not_before < earliest) earliest = record.not_before;
      if (!latest || record.not_before > latest) latest = record.not_before;
    }
  }

  return {
    domain,
    certificateCount: records.length,
    distinctIssuers: Array.from(issuers),
    earliestIssuance: earliest,
    latestIssuance: latest,
  };
}

/** Convenience: query crt.sh and immediately reduce to the scored summary. */
export async function queryDomainSummary(domain: string, options?: CrtShClientOptions): Promise<CrtShSummary> {
  const records = await queryDomain(domain, options);
  return summarizeCertificates(domain, records);
}

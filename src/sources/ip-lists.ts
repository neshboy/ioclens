const SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt";
const BLOCKLIST_DE_URL = "https://lists.blocklist.de/lists/all.txt";
const TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_USER_AGENT = "ioclens/0.1 (+https://github.com/) - IOC enrichment engine, IP blocklist lookup";

export interface IpListClientOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  userAgent?: string;
}

type ResolvedOptions = Required<IpListClientOptions>;

function resolveOptions(options?: IpListClientOptions): ResolvedOptions {
  return {
    fetchImpl: options?.fetchImpl ?? fetch,
    timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    userAgent: options?.userAgent ?? DEFAULT_USER_AGENT,
  };
}

async function fetchText(url: string, opts: ResolvedOptions): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
  let response: Response;
  try {
    response = await opts.fetchImpl(url, {
      signal: controller.signal,
      headers: { "User-Agent": opts.userAgent },
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`request to ${url} failed: ${reason}`);
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    throw new Error(`request to ${url} returned HTTP ${response.status}`);
  }
  return response.text();
}

export interface SpamhausDropEntry {
  cidr: string;
  sblId?: string;
}

/**
 * Parse the Spamhaus DROP list plain-text format:
 *   1.10.16.0/20 ; SBL256894
 * Lines starting with ";" are comments/header metadata and are skipped.
 */
export function parseSpamhausDrop(text: string): SpamhausDropEntry[] {
  const entries: SpamhausDropEntry[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(";")) continue;
    const [cidrPart, refPart] = trimmed.split(";").map((s) => s.trim());
    if (!cidrPart) continue;
    entries.push({ cidr: cidrPart, sblId: refPart || undefined });
  }
  return entries;
}

/** Parse a flat newline-delimited IP list (blocklist.de, Tor bulk exit list). */
export function parseFlatIpList(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
}

/**
 * Test whether an IPv4 address falls within an IPv4 CIDR block. IPv6 is not
 * supported (Spamhaus DROP is an IPv4-only list; DROPv6 is a separate feed
 * not integrated in this version - see README Limitations).
 */
export function isIpv4InCidr(ip: string, cidr: string): boolean {
  const [rangeIp, prefixLengthStr] = cidr.split("/");
  const prefixLength = Number(prefixLengthStr);
  if (!rangeIp || Number.isNaN(prefixLength) || prefixLength < 0 || prefixLength > 32) return false;

  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(rangeIp);
  if (ipInt === undefined || rangeInt === undefined) return false;

  if (prefixLength === 0) return true;
  const mask = (0xffffffff << (32 - prefixLength)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

function ipv4ToInt(ip: string): number | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) return undefined;
  let result = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return undefined;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

export async function fetchSpamhausDrop(options?: IpListClientOptions): Promise<SpamhausDropEntry[]> {
  const text = await fetchText(SPAMHAUS_DROP_URL, resolveOptions(options));
  return parseSpamhausDrop(text);
}

export async function fetchBlocklistDe(options?: IpListClientOptions): Promise<string[]> {
  const text = await fetchText(BLOCKLIST_DE_URL, resolveOptions(options));
  return parseFlatIpList(text);
}

export async function fetchTorExitList(options?: IpListClientOptions): Promise<string[]> {
  const text = await fetchText(TOR_EXIT_LIST_URL, resolveOptions(options));
  return parseFlatIpList(text);
}

export interface IpReputationSummary {
  ip: string;
  spamhausDrop: { checked: boolean; listed: boolean; matchedCidr?: string; sblId?: string; error?: string };
  blocklistDe: { checked: boolean; listed: boolean; error?: string };
  torExitNode: { checked: boolean; listed: boolean; error?: string };
}

/**
 * Cross-reference one IP against all three real, no-API-key IP lists in
 * parallel. Each list is checked independently and a failure in one does
 * not block the others - the caller (the scoring engine) treats an
 * unchecked list as "no signal", not as "clean".
 */
export async function checkIpReputation(ip: string, options?: IpListClientOptions): Promise<IpReputationSummary> {
  const [spamhaus, blocklistDe, tor] = await Promise.allSettled([
    fetchSpamhausDrop(options),
    fetchBlocklistDe(options),
    fetchTorExitList(options),
  ]);

  const summary: IpReputationSummary = {
    ip,
    spamhausDrop: { checked: false, listed: false },
    blocklistDe: { checked: false, listed: false },
    torExitNode: { checked: false, listed: false },
  };

  if (spamhaus.status === "fulfilled") {
    const match = spamhaus.value.find((entry) => isIpv4InCidr(ip, entry.cidr));
    summary.spamhausDrop = { checked: true, listed: !!match, matchedCidr: match?.cidr, sblId: match?.sblId };
  } else {
    summary.spamhausDrop = { checked: false, listed: false, error: describeError(spamhaus.reason) };
  }

  if (blocklistDe.status === "fulfilled") {
    summary.blocklistDe = { checked: true, listed: blocklistDe.value.includes(ip) };
  } else {
    summary.blocklistDe = { checked: false, listed: false, error: describeError(blocklistDe.reason) };
  }

  if (tor.status === "fulfilled") {
    summary.torExitNode = { checked: true, listed: tor.value.includes(ip) };
  } else {
    summary.torExitNode = { checked: false, listed: false, error: describeError(tor.reason) };
  }

  return summary;
}

function describeError(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason);
}

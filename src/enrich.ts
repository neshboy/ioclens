import { detectIndicator } from "./detect.js";
import type { EnrichmentResult, Signal, SourceResult } from "./types.js";
import { queryDomainSummary, type CrtShClientOptions } from "./sources/crtsh.js";
import { queryDomainRdap, queryIpRdap, type RdapClientOptions } from "./sources/rdap.js";
import { resolveDomain, reverseLookupIp, type DnsClientOptions } from "./sources/dns.js";
import { checkIpReputation, type IpListClientOptions } from "./sources/ip-lists.js";
import { scoreCertificatePattern, scoreDomainAge, scoreDomainDns, scoreIpDns, scoreIpRdap, scoreIpReputation, computeVerdict, buildReasoning } from "./scoring.js";

export interface EnrichOptions {
  crtsh?: CrtShClientOptions;
  rdap?: RdapClientOptions;
  dns?: DnsClientOptions;
  ipLists?: IpListClientOptions;
  now?: Date;
}

async function toSourceResult<T>(source: string, promise: Promise<T>): Promise<SourceResult<T>> {
  const started = Date.now();
  try {
    const data = await promise;
    return { source, status: "ok", durationMs: Date.now() - started, data };
  } catch (err) {
    return { source, status: "error", durationMs: Date.now() - started, error: err instanceof Error ? err.message : String(err) };
  }
}

async function enrichDomain(domain: string, options: EnrichOptions): Promise<Pick<EnrichmentResult, "signals" | "sources">> {
  const [rdap, crtsh, dns] = await Promise.all([
    toSourceResult("rdap", queryDomainRdap(domain, options.rdap)),
    toSourceResult("crtsh", queryDomainSummary(domain, options.crtsh)),
    toSourceResult("dns", resolveDomain(domain, options.dns)),
  ]);

  const now = options.now ?? new Date();
  const ageSignal = scoreDomainAge(rdap, now);
  const ageDays = rdap.status === "ok" && rdap.data?.found && rdap.data.registrationDate ? Math.floor((now.getTime() - new Date(rdap.data.registrationDate).getTime()) / 86_400_000) : undefined;

  const signals: Signal[] = [ageSignal, scoreCertificatePattern(crtsh, ageDays, now), scoreDomainDns(dns)];

  return { signals, sources: [rdap, crtsh, dns] };
}

async function enrichIp(ip: string, ipVersion: 4 | 6 | undefined, options: EnrichOptions): Promise<Pick<EnrichmentResult, "signals" | "sources">> {
  const [reputation, dns, rdap] = await Promise.all([
    toSourceResult("ip-lists", checkIpReputation(ip, options.ipLists, ipVersion)),
    toSourceResult("dns", reverseLookupIp(ip, options.dns)),
    toSourceResult("rdap", queryIpRdap(ip, options.rdap)),
  ]);

  const signals: Signal[] = [...scoreIpReputation(reputation), scoreIpDns(dns), scoreIpRdap(rdap)];

  return { signals, sources: [reputation, dns, rdap] };
}

/**
 * Run a full IOCLens enrichment pass on one indicator: detect its type,
 * query every applicable real OSINT source in parallel, score the
 * combined signals, and return one explained verdict. Individual source
 * failures are tolerated and surfaced (never silently swallowed) - a
 * degraded run still returns the best verdict available from whatever
 * data was actually obtained.
 */
export async function enrich(rawIndicator: string, options: EnrichOptions = {}): Promise<EnrichmentResult> {
  const indicator = detectIndicator(rawIndicator);
  const checkedAt = (options.now ?? new Date()).toISOString();

  if (indicator.type === "hash") {
    // Honest limitation (see README): no genuinely free, no-API-key hash
    // reputation source was found. abuse.ch's MalwareBazaar/URLhaus now
    // require a registered Auth-Key (verified during development - see
    // scripts/live-check.mts), so IOCLens does not fake a call to them.
    const signal: Signal = {
      id: "hash-no-source",
      source: "none",
      weight: 0,
      description: `No free, no-API-key hash-reputation OSINT source is integrated (researched: MalwareBazaar/URLhaus now require a registered Auth-Key - see README Limitations). Detected as ${indicator.hashAlgorithm?.toUpperCase()} by length only; no reputation lookup was performed.`,
    };
    return {
      indicator,
      verdict: "insufficient-data",
      score: 0,
      reasoning: buildReasoning([signal]),
      signals: [signal],
      sources: [],
      checkedAt,
    };
  }

  const { signals, sources } = indicator.type === "domain" ? await enrichDomain(indicator.value, options) : await enrichIp(indicator.value, indicator.ipVersion, options);

  const allSourcesFailed = sources.length > 0 && sources.every((s) => s.status === "error");
  if (allSourcesFailed) {
    return {
      indicator,
      verdict: "insufficient-data",
      score: 0,
      reasoning: [
        "All OSINT sources failed for this indicator - no verdict could be computed.",
        ...sources.map((s) => `  - ${s.source}: ${s.error ?? "unknown error"}`),
      ],
      signals,
      sources,
      checkedAt,
    };
  }

  const { score, verdict } = computeVerdict(signals);

  return {
    indicator,
    verdict,
    score,
    reasoning: buildReasoning(signals),
    signals,
    sources,
    checkedAt,
  };
}

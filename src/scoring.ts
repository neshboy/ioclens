import type { Signal, SourceResult, Verdict } from "./types.js";
import type { RdapDomainSummary, RdapIpSummary } from "./sources/rdap.js";
import type { CrtShSummary } from "./sources/crtsh.js";
import type { DomainDnsSummary, IpDnsSummary } from "./sources/dns.js";
import type { IpReputationSummary } from "./sources/ip-lists.js";

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function daysBetween(iso: string, now: Date): number | undefined {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return undefined;
  return Math.floor((now.getTime() - then.getTime()) / MS_PER_DAY);
}

/**
 * Domain age signal, derived from RDAP's `registration` event date.
 * Newly registered domains are one of the most consistently reliable
 * heuristics for throwaway phishing/malware infrastructure - legitimate
 * businesses rarely stand up a brand-new domain and immediately push
 * production traffic through it.
 */
export function scoreDomainAge(rdap: SourceResult<RdapDomainSummary>, now: Date = new Date()): Signal {
  const source = "rdap";
  if (rdap.status !== "ok" || !rdap.data) {
    return { id: "domain-age-unavailable", source, weight: 0, description: `RDAP registration lookup unavailable (${rdap.error ?? "skipped"}); domain-age scoring skipped.` };
  }
  if (!rdap.data.found) {
    return { id: "domain-age-not-found", source, weight: 0, description: "RDAP has no record for this domain (possible unregistered/lapsed domain or RDAP not supported by its registry)." };
  }
  if (!rdap.data.registrationDate) {
    return { id: "domain-age-no-date", source, weight: 0, description: "RDAP record found but did not include a registration date; domain-age scoring skipped." };
  }

  const ageDays = daysBetween(rdap.data.registrationDate, now);
  if (ageDays === undefined) {
    return { id: "domain-age-unparseable", source, weight: 0, description: `RDAP registration date "${rdap.data.registrationDate}" could not be parsed; domain-age scoring skipped.` };
  }

  if (ageDays < 0) {
    return { id: "domain-age-future", source, weight: 0, description: `RDAP registration date is in the future (${rdap.data.registrationDate}); treating as unreliable.` };
  }
  if (ageDays < 30) {
    return { id: "domain-age-new", source, weight: 30, description: `Domain was registered ${ageDays} day(s) ago (${rdap.data.registrationDate}) - very new domains are disproportionately used for disposable phishing/malware infrastructure.` };
  }
  if (ageDays < 90) {
    return { id: "domain-age-recent", source, weight: 15, description: `Domain was registered ${ageDays} days ago (${rdap.data.registrationDate}) - still recent enough to carry some risk weight.` };
  }
  if (ageDays < 365) {
    return { id: "domain-age-moderate", source, weight: 5, description: `Domain was registered ${ageDays} days ago (${rdap.data.registrationDate}) - under a year old, small residual risk weight.` };
  }
  return { id: "domain-age-established", source, weight: 0, description: `Domain was registered ${ageDays} days ago (${rdap.data.registrationDate}) - established domain, no age-based risk added.` };
}

/**
 * Certificate-issuance pattern signal from crt.sh. A certificate issued
 * within the last week on a domain that was ALSO just registered is a
 * strong, well-documented pattern for disposable attack infrastructure
 * (register domain -> immediately get a free cert -> stand up the site).
 * A domain with no logged certificates at all is a much weaker, purely
 * informational signal (plenty of legitimate domains don't serve HTTPS).
 */
export function scoreCertificatePattern(crtsh: SourceResult<CrtShSummary>, domainAgeDays: number | undefined): Signal {
  const source = "crtsh";
  if (crtsh.status !== "ok" || !crtsh.data) {
    return { id: "cert-pattern-unavailable", source, weight: 0, description: `crt.sh certificate-transparency lookup unavailable (${crtsh.error ?? "skipped"}); certificate scoring skipped.` };
  }

  const { certificateCount, latestIssuance, distinctIssuers } = crtsh.data;

  if (certificateCount === 0) {
    return { id: "cert-none-logged", source, weight: 5, description: "No certificates found in Certificate Transparency logs for this domain (crt.sh) - either it doesn't serve HTTPS, or it's too new for CT logs to have indexed yet." };
  }

  const latestAgeDays = latestIssuance ? daysBetween(latestIssuance, new Date()) : undefined;

  if (latestAgeDays !== undefined && latestAgeDays < 7 && domainAgeDays !== undefined && domainAgeDays < 30) {
    return {
      id: "cert-fresh-on-new-domain",
      source,
      weight: 20,
      description: `Most recent certificate was issued ${latestAgeDays} day(s) ago on a domain registered only ${domainAgeDays} day(s) ago - classic "stand up domain + cert together" pattern for disposable infrastructure.`,
    };
  }

  if (distinctIssuers.length > 5) {
    return {
      id: "cert-issuer-churn",
      source,
      weight: 10,
      description: `${certificateCount} certificate(s) logged from ${distinctIssuers.length} distinct issuing CAs - unusually high churn for one domain.`,
    };
  }

  return {
    id: "cert-normal",
    source,
    weight: 0,
    description: `${certificateCount} certificate(s) logged in Certificate Transparency for this domain, issuance pattern unremarkable.`,
  };
}

/**
 * DNS resolution signal for a domain. Non-resolution isn't proof of
 * malice (parked/sinkholed/not-yet-live domains all look the same from
 * here) but a registered domain with no active DNS is still a real,
 * distinct observation worth a small weight.
 */
export function scoreDomainDns(dns: SourceResult<DomainDnsSummary>): Signal {
  const source = "dns";
  if (dns.status !== "ok" || !dns.data) {
    return { id: "dns-unavailable", source, weight: 0, description: `DNS resolution check unavailable (${dns.error ?? "skipped"}).` };
  }
  if (!dns.data.resolves) {
    return { id: "dns-no-resolution", source, weight: 10, description: "Domain does not currently resolve to any A/AAAA record (NXDOMAIN or empty) - registered but not actively serving." };
  }
  return { id: "dns-resolves", source, weight: 0, description: `Domain resolves to ${dns.data.addresses.length} address(es) (${dns.data.addresses.slice(0, 3).join(", ")}${dns.data.addresses.length > 3 ? ", ..." : ""}).` };
}

/**
 * IP reputation signal from real, no-API-key blocklists. Spamhaus DROP is
 * an authoritative, actively-maintained list of netblocks hijacked or
 * leased specifically for spam/malware hosting, so a hit there is a
 * strong signal. blocklist.de is community fail2ban-style abuse
 * reporting (real but noisier). Tor exit-node membership is informational
 * only - anonymization is not itself malicious.
 */
export function scoreIpReputation(reputation: SourceResult<IpReputationSummary>): Signal[] {
  const source = "ip-lists";
  if (reputation.status !== "ok" || !reputation.data) {
    return [{ id: "ip-reputation-unavailable", source, weight: 0, description: `IP blocklist cross-reference unavailable (${reputation.error ?? "skipped"}).` }];
  }

  const signals: Signal[] = [];
  const { spamhausDrop, blocklistDe, torExitNode } = reputation.data;

  if (spamhausDrop.checked) {
    signals.push(
      spamhausDrop.listed
        ? { id: "spamhaus-drop-listed", source: "spamhaus-drop", weight: 50, description: `IP falls within a Spamhaus DROP netblock (${spamhausDrop.matchedCidr}${spamhausDrop.sblId ? `, ${spamhausDrop.sblId}` : ""}) - an authoritative list of netblocks controlled by spammers/malware operators.` }
        : { id: "spamhaus-drop-clean", source: "spamhaus-drop", weight: 0, description: "IP is not within any Spamhaus DROP netblock." },
    );
  } else {
    signals.push({ id: "spamhaus-drop-unchecked", source: "spamhaus-drop", weight: 0, description: `Spamhaus DROP list unavailable (${spamhausDrop.error ?? "skipped"}).` });
  }

  if (blocklistDe.checked) {
    signals.push(
      blocklistDe.listed
        ? { id: "blocklist-de-listed", source: "blocklist.de", weight: 25, description: "IP appears on blocklist.de's aggregated fail2ban/abuse-report list (community-reported attack activity, e.g. brute force or scanning)." }
        : { id: "blocklist-de-clean", source: "blocklist.de", weight: 0, description: "IP is not on blocklist.de's aggregated abuse-report list." },
    );
  } else {
    signals.push({ id: "blocklist-de-unchecked", source: "blocklist.de", weight: 0, description: `blocklist.de list unavailable (${blocklistDe.error ?? "skipped"}).` });
  }

  if (torExitNode.checked) {
    signals.push(
      torExitNode.listed
        ? { id: "tor-exit-node", source: "tor", weight: 10, description: "IP is a currently-listed Tor exit node - anonymized traffic source, not inherently malicious but often relevant context for abuse investigations." }
        : { id: "tor-not-exit", source: "tor", weight: 0, description: "IP is not a currently-listed Tor exit node." },
    );
  } else {
    signals.push({ id: "tor-unchecked", source: "tor", weight: 0, description: `Tor exit-node list unavailable (${torExitNode.error ?? "skipped"}).` });
  }

  return signals;
}

/** Reverse-DNS signal for an IP. Purely informational context, never scored: absence of a PTR record is extremely common on legitimate hosts. */
export function scoreIpDns(dns: SourceResult<IpDnsSummary>): Signal {
  const source = "dns";
  if (dns.status !== "ok" || !dns.data) {
    return { id: "reverse-dns-unavailable", source, weight: 0, description: `Reverse DNS lookup unavailable (${dns.error ?? "skipped"}).` };
  }
  if (dns.data.hasReverseRecord) {
    return { id: "reverse-dns-present", source, weight: 0, description: `IP has a reverse DNS (PTR) record: ${dns.data.hostnames.join(", ")}.` };
  }
  return { id: "reverse-dns-absent", source, weight: 0, description: "IP has no reverse DNS (PTR) record. Common on legitimate hosts too; informational only." };
}

/** Registry/allocation context for an IP via RDAP. Informational only: allocation age reflects ASN history, not the current occupant's behavior. */
export function scoreIpRdap(rdap: SourceResult<RdapIpSummary>): Signal {
  const source = "rdap";
  if (rdap.status !== "ok" || !rdap.data || !rdap.data.found) {
    return { id: "ip-rdap-unavailable", source, weight: 0, description: `RDAP network lookup unavailable (${rdap.status === "ok" ? "no record found" : rdap.error ?? "skipped"}).` };
  }
  const parts = [rdap.data.networkName, rdap.data.organization, rdap.data.country].filter(Boolean);
  return { id: "ip-rdap-context", source, weight: 0, description: `Network: ${parts.length > 0 ? parts.join(", ") : "(no name/org/country on record)"}${rdap.data.cidr ? ` (${rdap.data.cidr})` : ""}.` };
}

const VERDICT_THRESHOLDS: Array<{ max: number; verdict: Verdict }> = [
  { max: 0, verdict: "clean" },
  { max: 24, verdict: "low-risk" },
  { max: 49, verdict: "suspicious" },
  { max: Infinity, verdict: "high-risk" },
];

/**
 * Sum signal weights into a single 0-100 score and bucket it into a
 * deterministic verdict. No ML, no hidden logic - every point in the score
 * traces back to one `Signal` with a human-readable `description`.
 */
export function computeVerdict(signals: Signal[]): { score: number; verdict: Verdict } {
  const rawScore = signals.reduce((sum, s) => sum + s.weight, 0);
  const score = Math.max(0, Math.min(100, rawScore));
  const bucket = VERDICT_THRESHOLDS.find((t) => score <= t.max);
  return { score, verdict: bucket?.verdict ?? "high-risk" };
}

/** Render the ordered, human-readable reasoning lines from a signal list (only non-empty descriptions, in evaluation order). */
export function buildReasoning(signals: Signal[]): string[] {
  return signals.filter((s) => s.description).map((s) => (s.weight > 0 ? `[+${s.weight}] ${s.description}` : s.description));
}

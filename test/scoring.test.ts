import { describe, expect, it } from "vitest";
import { buildReasoning, computeVerdict, scoreCertificatePattern, scoreDomainAge, scoreDomainDns, scoreIpDns, scoreIpReputation } from "../src/scoring.js";
import type { SourceResult } from "../src/types.js";
import type { RdapDomainSummary } from "../src/sources/rdap.js";
import type { CrtShSummary } from "../src/sources/crtsh.js";
import type { DomainDnsSummary, IpDnsSummary } from "../src/sources/dns.js";
import type { IpReputationSummary } from "../src/sources/ip-lists.js";

const NOW = new Date("2026-09-24T00:00:00Z");

function ok<T>(data: T, source = "test"): SourceResult<T> {
  return { source, status: "ok", data };
}

function errored<T>(error: string, source = "test"): SourceResult<T> {
  return { source, status: "error", error };
}

describe("scoreDomainAge", () => {
  it("weights a domain registered 5 days ago as domain-age-new (+30)", () => {
    const rdap: SourceResult<RdapDomainSummary> = ok({ domain: "x.com", found: true, registrationDate: "2026-09-19T00:00:00Z", status: [] });
    const signal = scoreDomainAge(rdap, NOW);
    expect(signal.id).toBe("domain-age-new");
    expect(signal.weight).toBe(30);
  });

  it("weights a domain registered 60 days ago as domain-age-recent (+15)", () => {
    const rdap: SourceResult<RdapDomainSummary> = ok({ domain: "x.com", found: true, registrationDate: "2026-07-26T00:00:00Z", status: [] });
    const signal = scoreDomainAge(rdap, NOW);
    expect(signal.id).toBe("domain-age-recent");
    expect(signal.weight).toBe(15);
  });

  it("weights a domain registered 10 years ago as domain-age-established (0)", () => {
    const rdap: SourceResult<RdapDomainSummary> = ok({ domain: "x.com", found: true, registrationDate: "2016-01-01T00:00:00Z", status: [] });
    const signal = scoreDomainAge(rdap, NOW);
    expect(signal.id).toBe("domain-age-established");
    expect(signal.weight).toBe(0);
  });

  it("assigns weight 0 when RDAP failed", () => {
    const signal = scoreDomainAge(errored("timeout"), NOW);
    expect(signal.weight).toBe(0);
    expect(signal.id).toBe("domain-age-unavailable");
  });

  it("assigns weight 0 when RDAP has no record", () => {
    const rdap: SourceResult<RdapDomainSummary> = ok({ domain: "x.com", found: false, status: [] });
    const signal = scoreDomainAge(rdap, NOW);
    expect(signal.id).toBe("domain-age-not-found");
    expect(signal.weight).toBe(0);
  });
});

describe("scoreCertificatePattern", () => {
  it("scores a fresh cert on a brand-new domain highly (+20)", () => {
    const crtsh: SourceResult<CrtShSummary> = ok({ domain: "x.com", certificateCount: 1, distinctIssuers: ["Let's Encrypt"], latestIssuance: "2026-09-20T00:00:00Z" });
    const signal = scoreCertificatePattern(crtsh, 5, NOW);
    expect(signal.id).toBe("cert-fresh-on-new-domain");
    expect(signal.weight).toBe(20);
  });

  it("does not flag a fresh cert on an old domain (renewal is normal)", () => {
    const crtsh: SourceResult<CrtShSummary> = ok({ domain: "x.com", certificateCount: 1, distinctIssuers: ["Let's Encrypt"], latestIssuance: "2026-09-20T00:00:00Z" });
    const signal = scoreCertificatePattern(crtsh, 3650, NOW);
    expect(signal.id).not.toBe("cert-fresh-on-new-domain");
  });

  it("flags unusually high issuer churn", () => {
    const crtsh: SourceResult<CrtShSummary> = ok({
      domain: "x.com",
      certificateCount: 12,
      distinctIssuers: ["A", "B", "C", "D", "E", "F"],
      latestIssuance: "2020-01-01T00:00:00Z",
    });
    const signal = scoreCertificatePattern(crtsh, 3650, NOW);
    expect(signal.id).toBe("cert-issuer-churn");
    expect(signal.weight).toBe(10);
  });

  it("weakly flags zero certificates found", () => {
    const crtsh: SourceResult<CrtShSummary> = ok({ domain: "x.com", certificateCount: 0, distinctIssuers: [] });
    const signal = scoreCertificatePattern(crtsh, undefined);
    expect(signal.id).toBe("cert-none-logged");
    expect(signal.weight).toBe(5);
  });
});

describe("scoreDomainDns", () => {
  it("flags non-resolving domains with weight 10", () => {
    const dns: SourceResult<DomainDnsSummary> = ok({ domain: "x.com", resolves: false, addresses: [] });
    expect(scoreDomainDns(dns).weight).toBe(10);
  });

  it("gives weight 0 to a resolving domain", () => {
    const dns: SourceResult<DomainDnsSummary> = ok({ domain: "x.com", resolves: true, addresses: ["1.2.3.4"] });
    expect(scoreDomainDns(dns).weight).toBe(0);
  });
});

describe("scoreIpReputation", () => {
  it("weights a Spamhaus DROP hit at +50", () => {
    const reputation: SourceResult<IpReputationSummary> = ok({
      ip: "1.2.3.4",
      spamhausDrop: { checked: true, listed: true, matchedCidr: "1.2.3.0/24" },
      blocklistDe: { checked: true, listed: false },
      torExitNode: { checked: true, listed: false },
    });
    const signals = scoreIpReputation(reputation);
    const total = signals.reduce((s, sig) => s + sig.weight, 0);
    expect(total).toBe(50);
    expect(signals.some((s) => s.id === "spamhaus-drop-listed")).toBe(true);
  });

  it("sums independent hits across all three lists", () => {
    const reputation: SourceResult<IpReputationSummary> = ok({
      ip: "1.2.3.4",
      spamhausDrop: { checked: true, listed: true, matchedCidr: "1.2.3.0/24" },
      blocklistDe: { checked: true, listed: true },
      torExitNode: { checked: true, listed: true },
    });
    const total = scoreIpReputation(reputation).reduce((s, sig) => s + sig.weight, 0);
    expect(total).toBe(85);
  });
});

describe("scoreIpDns", () => {
  it("never assigns weight regardless of reverse DNS presence (informational only)", () => {
    const withPtr: SourceResult<IpDnsSummary> = ok({ ip: "1.2.3.4", hasReverseRecord: true, hostnames: ["host.example.com"] });
    const withoutPtr: SourceResult<IpDnsSummary> = ok({ ip: "1.2.3.4", hasReverseRecord: false, hostnames: [] });
    expect(scoreIpDns(withPtr).weight).toBe(0);
    expect(scoreIpDns(withoutPtr).weight).toBe(0);
  });
});

describe("computeVerdict", () => {
  it("returns clean for a total score of 0", () => {
    expect(computeVerdict([{ id: "a", source: "s", weight: 0, description: "x" }])).toEqual({ score: 0, verdict: "clean" });
  });

  it("returns low-risk for a small positive score", () => {
    expect(computeVerdict([{ id: "a", source: "s", weight: 10, description: "x" }])).toEqual({ score: 10, verdict: "low-risk" });
  });

  it("returns suspicious for a mid-range score", () => {
    expect(computeVerdict([{ id: "a", source: "s", weight: 30, description: "x" }])).toEqual({ score: 30, verdict: "suspicious" });
  });

  it("returns high-risk for a large score", () => {
    expect(computeVerdict([{ id: "a", source: "s", weight: 50, description: "x" }])).toEqual({ score: 50, verdict: "high-risk" });
  });

  it("clamps the score at 100", () => {
    const signals = [
      { id: "a", source: "s", weight: 60, description: "x" },
      { id: "b", source: "s", weight: 60, description: "y" },
    ];
    expect(computeVerdict(signals)).toEqual({ score: 100, verdict: "high-risk" });
  });
});

describe("buildReasoning", () => {
  it("prefixes weighted signals with their point contribution and leaves zero-weight signals unprefixed", () => {
    const lines = buildReasoning([
      { id: "a", source: "s", weight: 30, description: "new domain" },
      { id: "b", source: "s", weight: 0, description: "resolves fine" },
    ]);
    expect(lines).toEqual(["[+30] new domain", "resolves fine"]);
  });
});

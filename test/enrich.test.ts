import { describe, expect, it, vi } from "vitest";
import { enrich } from "../src/enrich.js";
import type { DnsResolver } from "../src/sources/dns.js";

const NOW = new Date("2026-09-24T00:00:00Z");

function jsonResponse(body: unknown, status = 200): { ok: boolean; status: number; text: () => Promise<string> } {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) };
}

describe("enrich (domain, fully mocked/offline)", () => {
  it("scores a freshly-registered domain with a fresh matching certificate as high-risk", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.startsWith("https://rdap.org/domain/")) {
        return jsonResponse({
          events: [{ eventAction: "registration", eventDate: "2026-09-20T00:00:00Z" }],
          status: [],
        });
      }
      if (url.startsWith("https://crt.sh/")) {
        return { ok: true, status: 200, text: async () => JSON.stringify([{ issuer_ca_id: 1, issuer_name: "Let's Encrypt", common_name: "totally-legit-bank-login.com", name_value: "totally-legit-bank-login.com", id: 1, entry_timestamp: "2026-09-21T00:00:00", not_before: "2026-09-21T00:00:00", not_after: "2026-12-21T00:00:00", serial_number: "1" }]) };
      }
      throw new Error(`unexpected fetch to ${url}`);
    }) as unknown as typeof fetch;

    const resolver: DnsResolver = {
      resolve4: async () => ["203.0.113.9"],
      resolve6: async () => {
        throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      },
      reverse: async () => [],
    };

    const result = await enrich("totally-legit-bank-login.com", {
      rdap: { fetchImpl },
      crtsh: { fetchImpl },
      dns: { resolver },
      now: NOW,
    });

    expect(result.indicator.type).toBe("domain");
    expect(result.verdict).toBe("high-risk");
    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(result.sources.every((s) => s.status === "ok")).toBe(true);
    expect(result.reasoning.some((line) => line.includes("registered"))).toBe(true);
  });

  it("scores an established domain with normal signals as clean", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.startsWith("https://rdap.org/domain/")) {
        return jsonResponse({
          events: [{ eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" }],
          status: [],
        });
      }
      if (url.startsWith("https://crt.sh/")) {
        return { ok: true, status: 200, text: async () => JSON.stringify([{ issuer_ca_id: 1, issuer_name: "DigiCert", common_name: "example.com", name_value: "example.com", id: 1, entry_timestamp: "2026-01-01T00:00:00", not_before: "2026-01-01T00:00:00", not_after: "2026-06-01T00:00:00", serial_number: "1" }]) };
      }
      throw new Error(`unexpected fetch to ${url}`);
    }) as unknown as typeof fetch;

    const resolver: DnsResolver = {
      resolve4: async () => ["93.184.216.34"],
      resolve6: async () => [],
      reverse: async () => [],
    };

    const result = await enrich("example.com", { rdap: { fetchImpl }, crtsh: { fetchImpl }, dns: { resolver }, now: NOW });

    expect(result.verdict).toBe("clean");
    expect(result.score).toBe(0);
  });

  it("falls back to insufficient-data when every source errors", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("network down")) as unknown as typeof fetch;
    const resolver: DnsResolver = {
      resolve4: async () => {
        throw Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" });
      },
      resolve6: async () => {
        throw Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" });
      },
      reverse: async () => [],
    };

    const result = await enrich("example.com", { rdap: { fetchImpl }, crtsh: { fetchImpl }, dns: { resolver }, now: NOW });
    expect(result.verdict).toBe("insufficient-data");
  });
});

describe("enrich (IP, fully mocked/offline)", () => {
  it("scores an IP found in the Spamhaus DROP list as high-risk", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes("spamhaus")) return { ok: true, status: 200, text: async () => "198.51.100.0/24 ; SBL999999\n" };
      if (url.includes("blocklist.de")) return { ok: true, status: 200, text: async () => "" };
      if (url.includes("torproject")) return { ok: true, status: 200, text: async () => "" };
      if (url.startsWith("https://rdap.org/ip/")) return jsonResponse({ name: "TEST-NET", country: "ZZ", events: [], entities: [] });
      throw new Error(`unexpected fetch to ${url}`);
    }) as unknown as typeof fetch;

    const resolver: DnsResolver = {
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => {
        throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      },
    };

    const result = await enrich("198.51.100.42", { ipLists: { fetchImpl }, rdap: { fetchImpl }, dns: { resolver }, now: NOW });

    expect(result.indicator.type).toBe("ip");
    expect(result.verdict).toBe("high-risk");
    expect(result.score).toBe(50);
    expect(result.reasoning.some((line) => line.includes("Spamhaus DROP"))).toBe(true);
  });

  it("scores a clean IP with no reverse DNS as clean (informational-only signals don't add weight)", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes("spamhaus")) return { ok: true, status: 200, text: async () => "198.51.100.0/24 ; SBL999999\n" };
      if (url.includes("blocklist.de")) return { ok: true, status: 200, text: async () => "" };
      if (url.includes("torproject")) return { ok: true, status: 200, text: async () => "" };
      if (url.startsWith("https://rdap.org/ip/")) return jsonResponse({ name: "GOOGLE", country: "US", events: [], entities: [] });
      throw new Error(`unexpected fetch to ${url}`);
    }) as unknown as typeof fetch;

    const resolver: DnsResolver = {
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => {
        throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      },
    };

    const result = await enrich("8.8.8.8", { ipLists: { fetchImpl }, rdap: { fetchImpl }, dns: { resolver }, now: NOW });
    expect(result.verdict).toBe("clean");
    expect(result.score).toBe(0);
  });
});

describe("enrich (hash)", () => {
  it("returns insufficient-data and does not perform any network lookups", async () => {
    const fetchImpl = vi.fn() as unknown as typeof fetch;
    const result = await enrich("d41d8cd98f00b204e9800998ecf8427e", { rdap: { fetchImpl }, crtsh: { fetchImpl }, ipLists: { fetchImpl } });

    expect(result.indicator.type).toBe("hash");
    expect(result.indicator.hashAlgorithm).toBe("md5");
    expect(result.verdict).toBe("insufficient-data");
    expect(result.sources).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

import { describe, expect, it, vi } from "vitest";
import { checkIpReputation, isIpv4InCidr, parseFlatIpList, parseSpamhausDrop } from "../src/sources/ip-lists.js";

describe("parseSpamhausDrop", () => {
  it("parses real-shaped DROP list lines and skips comments/headers", () => {
    const text = [
      "; Spamhaus DROP List 2026/09/22",
      "; https://www.spamhaus.org/drop/drop.txt",
      "1.10.16.0/20 ; SBL256894",
      "2.56.192.0/22 ; SBL459831",
      "",
    ].join("\n");

    const entries = parseSpamhausDrop(text);
    expect(entries).toEqual([
      { cidr: "1.10.16.0/20", sblId: "SBL256894" },
      { cidr: "2.56.192.0/22", sblId: "SBL459831" },
    ]);
  });
});

describe("parseFlatIpList", () => {
  it("parses a newline-delimited list and drops blank lines / comments", () => {
    const text = "1.2.3.4\n\n# comment\n5.6.7.8\n";
    expect(parseFlatIpList(text)).toEqual(["1.2.3.4", "5.6.7.8"]);
  });
});

describe("isIpv4InCidr", () => {
  it("matches an IP within a /20 block", () => {
    expect(isIpv4InCidr("1.10.20.5", "1.10.16.0/20")).toBe(true);
  });

  it("does not match an IP outside the block", () => {
    expect(isIpv4InCidr("1.11.0.1", "1.10.16.0/20")).toBe(false);
  });

  it("matches an exact /32", () => {
    expect(isIpv4InCidr("8.8.8.8", "8.8.8.8/32")).toBe(true);
    expect(isIpv4InCidr("8.8.8.9", "8.8.8.8/32")).toBe(false);
  });

  it("matches everything for /0", () => {
    expect(isIpv4InCidr("203.0.113.1", "0.0.0.0/0")).toBe(true);
  });

  it("returns false for malformed CIDR input", () => {
    expect(isIpv4InCidr("1.2.3.4", "not-a-cidr")).toBe(false);
    expect(isIpv4InCidr("1.2.3.4", "1.2.3.4/99")).toBe(false);
  });
});

function mockFetchText(responses: Record<string, string>): typeof fetch {
  return vi.fn(async (url: string) => {
    const body = responses[url];
    if (body === undefined) {
      return { ok: false, status: 404, text: async () => "" } as unknown as Response;
    }
    return { ok: true, status: 200, text: async () => body } as unknown as Response;
  }) as unknown as typeof fetch;
}

describe("checkIpReputation", () => {
  it("cross-references all three lists and reports a match from Spamhaus DROP", async () => {
    const fetchImpl = mockFetchText({
      "https://www.spamhaus.org/drop/drop.txt": "1.10.16.0/20 ; SBL256894\n",
      "https://lists.blocklist.de/lists/all.txt": "9.9.9.9\n",
      "https://check.torproject.org/torbulkexitlist": "203.0.113.5\n",
    });

    const result = await checkIpReputation("1.10.20.5", { fetchImpl });

    expect(result.spamhausDrop.checked).toBe(true);
    expect(result.spamhausDrop.listed).toBe(true);
    expect(result.spamhausDrop.matchedCidr).toBe("1.10.16.0/20");
    expect(result.blocklistDe.listed).toBe(false);
    expect(result.torExitNode.listed).toBe(false);
  });

  it("reports clean across all lists when the IP appears in none", async () => {
    const fetchImpl = mockFetchText({
      "https://www.spamhaus.org/drop/drop.txt": "1.10.16.0/20 ; SBL256894\n",
      "https://lists.blocklist.de/lists/all.txt": "9.9.9.9\n",
      "https://check.torproject.org/torbulkexitlist": "203.0.113.5\n",
    });

    const result = await checkIpReputation("192.0.2.1", { fetchImpl });
    expect(result.spamhausDrop.listed).toBe(false);
    expect(result.blocklistDe.listed).toBe(false);
    expect(result.torExitNode.listed).toBe(false);
  });

  it("degrades gracefully when one list fails, without failing the others", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes("spamhaus")) throw new Error("spamhaus timeout");
      if (url.includes("blocklist.de")) return { ok: true, status: 200, text: async () => "9.9.9.9\n" } as unknown as Response;
      return { ok: true, status: 200, text: async () => "" } as unknown as Response;
    }) as unknown as typeof fetch;

    const result = await checkIpReputation("9.9.9.9", { fetchImpl });
    expect(result.spamhausDrop.checked).toBe(false);
    expect(result.spamhausDrop.error).toMatch(/timeout/);
    expect(result.blocklistDe.checked).toBe(true);
    expect(result.blocklistDe.listed).toBe(true);
  });
});

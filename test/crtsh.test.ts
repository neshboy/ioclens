import { describe, expect, it, vi } from "vitest";
import { buildCrtShUrl, queryDomain, summarizeCertificates } from "../src/sources/crtsh.js";
import type { CrtShCertificate } from "../src/sources/crtsh.js";

const SAMPLE_CERT: CrtShCertificate = {
  issuer_ca_id: 432477,
  issuer_name: "C=US, O=Let's Encrypt, CN=R3",
  common_name: "example-lookalike.com",
  name_value: "example-lookalike.com",
  id: 123456789,
  entry_timestamp: "2026-01-01T00:00:00",
  not_before: "2026-01-01T00:00:00",
  not_after: "2026-04-01T00:00:00",
  serial_number: "0abc123",
};

function mockFetchOnce(response: { ok: boolean; status?: number; body?: string }): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok: response.ok,
    status: response.status ?? (response.ok ? 200 : 500),
    text: async () => response.body ?? "",
  }) as unknown as typeof fetch;
}

describe("buildCrtShUrl", () => {
  it("builds a URL against the real crt.sh JSON endpoint", () => {
    const url = buildCrtShUrl("example.com");
    expect(url.startsWith("https://crt.sh/?")).toBe(true);
    expect(url).toContain("q=example.com");
    expect(url).toContain("output=json");
  });
});

describe("queryDomain", () => {
  it("parses a mocked crt.sh JSON response into certificate records", async () => {
    const fetchImpl = mockFetchOnce({ ok: true, body: JSON.stringify([SAMPLE_CERT]) });

    const results = await queryDomain("example-lookalike.com", { fetchImpl });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const calledUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(calledUrl).toContain("q=example-lookalike.com");

    expect(results).toHaveLength(1);
    expect(results[0].id).toBe(123456789);
  });

  it("returns an empty array when crt.sh has no matches (empty body)", async () => {
    const fetchImpl = mockFetchOnce({ ok: true, body: "" });
    const results = await queryDomain("no-such-domain-xyz123.com", { fetchImpl });
    expect(results).toEqual([]);
  });

  it("throws a descriptive error on a non-2xx HTTP response", async () => {
    const fetchImpl = mockFetchOnce({ ok: false, status: 503 });
    await expect(queryDomain("example.com", { fetchImpl })).rejects.toThrow(/503/);
  });

  it("throws a descriptive error when crt.sh returns non-JSON (e.g. an overloaded HTML page)", async () => {
    const fetchImpl = mockFetchOnce({ ok: true, body: "<html>Service Unavailable</html>" });
    await expect(queryDomain("example.com", { fetchImpl })).rejects.toThrow(/non-JSON|overloaded/);
  });

  it("propagates a network-level failure (e.g. timeout/abort) as a descriptive error", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("network error")) as unknown as typeof fetch;
    await expect(queryDomain("example.com", { fetchImpl })).rejects.toThrow(/crt\.sh request .* failed/);
  });
});

describe("summarizeCertificates", () => {
  it("summarizes an empty record list", () => {
    const summary = summarizeCertificates("example.com", []);
    expect(summary.certificateCount).toBe(0);
    expect(summary.distinctIssuers).toEqual([]);
    expect(summary.earliestIssuance).toBeUndefined();
    expect(summary.latestIssuance).toBeUndefined();
  });

  it("computes distinct issuers and earliest/latest issuance across multiple records", () => {
    const older = { ...SAMPLE_CERT, id: 1, not_before: "2025-01-01T00:00:00", issuer_name: "Issuer A" };
    const newer = { ...SAMPLE_CERT, id: 2, not_before: "2026-06-01T00:00:00", issuer_name: "Issuer B" };
    const middle = { ...SAMPLE_CERT, id: 3, not_before: "2025-06-01T00:00:00", issuer_name: "Issuer A" };

    const summary = summarizeCertificates("example.com", [older, newer, middle]);

    expect(summary.certificateCount).toBe(3);
    expect(summary.distinctIssuers.sort()).toEqual(["Issuer A", "Issuer B"]);
    expect(summary.earliestIssuance).toBe("2025-01-01T00:00:00");
    expect(summary.latestIssuance).toBe("2026-06-01T00:00:00");
  });
});

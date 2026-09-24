import { describe, expect, it, vi } from "vitest";
import { queryDomainRdap, queryIpRdap } from "../src/sources/rdap.js";

function mockFetchJson(body: unknown, status = 200): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  }) as unknown as typeof fetch;
}

const DOMAIN_RESPONSE = {
  objectClassName: "domain",
  ldhName: "EXAMPLE.COM",
  handle: "2336799_DOMAIN_COM-VRSN",
  status: ["client delete prohibited", "client transfer prohibited"],
  events: [
    { eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" },
    { eventAction: "expiration", eventDate: "2027-08-13T04:00:00Z" },
    { eventAction: "last changed", eventDate: "2026-08-14T07:01:44Z" },
  ],
  entities: [
    {
      objectClassName: "entity",
      roles: ["registrar"],
      vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar Inc."]]],
    },
  ],
};

const IP_RESPONSE = {
  objectClassName: "ip network",
  handle: "NET-8-8-8-0-1",
  startAddress: "8.8.8.0",
  endAddress: "8.8.8.255",
  name: "GOGL",
  type: "ALLOCATED",
  country: "US",
  cidr0_cidrs: [{ v4prefix: "8.8.8.0", length: 24 }],
  events: [{ eventAction: "registration", eventDate: "2014-03-14T00:00:00Z" }],
  entities: [],
};

describe("queryDomainRdap", () => {
  it("parses registration/expiration dates and registrar name from a real-shaped RDAP domain response", async () => {
    const fetchImpl = mockFetchJson(DOMAIN_RESPONSE);
    const result = await queryDomainRdap("example.com", { fetchImpl });

    expect(result.found).toBe(true);
    expect(result.registrationDate).toBe("1995-08-14T04:00:00Z");
    expect(result.expirationDate).toBe("2027-08-13T04:00:00Z");
    expect(result.registrarName).toBe("Example Registrar Inc.");
    expect(result.status).toContain("client delete prohibited");

    const calledUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(calledUrl).toBe("https://rdap.org/domain/example.com");
  });

  it("returns found:false on a 404 (unregistered/unsupported domain)", async () => {
    const fetchImpl = mockFetchJson({ errorCode: 404, title: "Not Found" }, 404);
    const result = await queryDomainRdap("no-such-domain-xyz123.invalid", { fetchImpl });
    expect(result.found).toBe(false);
  });

  it("throws a descriptive error on a non-404 non-2xx response", async () => {
    const fetchImpl = mockFetchJson({}, 503);
    await expect(queryDomainRdap("example.com", { fetchImpl })).rejects.toThrow(/503/);
  });

  it("throws a descriptive error on a network failure", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("boom")) as unknown as typeof fetch;
    await expect(queryDomainRdap("example.com", { fetchImpl })).rejects.toThrow(/RDAP request .* failed/);
  });
});

describe("queryIpRdap", () => {
  it("parses network name, country, and CIDR from a real-shaped RDAP IP response", async () => {
    const fetchImpl = mockFetchJson(IP_RESPONSE);
    const result = await queryIpRdap("8.8.8.8", { fetchImpl });

    expect(result.found).toBe(true);
    expect(result.networkName).toBe("GOGL");
    expect(result.country).toBe("US");
    expect(result.cidr).toBe("8.8.8.0/24");

    const calledUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(calledUrl).toBe("https://rdap.org/ip/8.8.8.8");
  });

  it("returns found:false on a 404", async () => {
    const fetchImpl = mockFetchJson({}, 404);
    const result = await queryIpRdap("192.0.2.1", { fetchImpl });
    expect(result.found).toBe(false);
  });
});

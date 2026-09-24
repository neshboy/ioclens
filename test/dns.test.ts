import { describe, expect, it } from "vitest";
import { resolveDomain, reverseLookupIp } from "../src/sources/dns.js";
import type { DnsResolver } from "../src/sources/dns.js";

function notFoundError(): NodeJS.ErrnoException {
  const err = new Error("queryA ENOTFOUND example.invalid") as NodeJS.ErrnoException;
  err.code = "ENOTFOUND";
  return err;
}

describe("resolveDomain", () => {
  it("returns resolves:true with combined v4/v6 addresses when both succeed", async () => {
    const resolver: DnsResolver = {
      resolve4: async () => ["93.184.216.34"],
      resolve6: async () => ["2606:2800:220:1:248:1893:25c8:1946"],
      reverse: async () => [],
    };
    const result = await resolveDomain("example.com", { resolver });
    expect(result.resolves).toBe(true);
    expect(result.addresses).toEqual(["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]);
  });

  it("returns resolves:true when only v4 succeeds", async () => {
    const resolver: DnsResolver = {
      resolve4: async () => ["93.184.216.34"],
      resolve6: async () => {
        throw notFoundError();
      },
      reverse: async () => [],
    };
    const result = await resolveDomain("example.com", { resolver });
    expect(result.resolves).toBe(true);
    expect(result.addresses).toEqual(["93.184.216.34"]);
  });

  it("returns resolves:false with no error when both v4 and v6 are NXDOMAIN", async () => {
    const resolver: DnsResolver = {
      resolve4: async () => {
        throw notFoundError();
      },
      resolve6: async () => {
        throw notFoundError();
      },
      reverse: async () => [],
    };
    const result = await resolveDomain("no-such-domain-xyz123.invalid", { resolver });
    expect(result.resolves).toBe(false);
    expect(result.addresses).toEqual([]);
    expect(result.error).toBeUndefined();
  });

  it("throws (rather than reporting non-resolution) on a genuine resolver error (not NXDOMAIN)", async () => {
    const timeoutErr = new Error("queryA ETIMEOUT") as NodeJS.ErrnoException;
    timeoutErr.code = "ETIMEOUT";
    const resolver: DnsResolver = {
      resolve4: async () => {
        throw timeoutErr;
      },
      resolve6: async () => {
        throw notFoundError();
      },
      reverse: async () => [],
    };
    await expect(resolveDomain("example.com", { resolver })).rejects.toThrow(/ETIMEOUT/);
  });
});

describe("reverseLookupIp", () => {
  it("returns hasReverseRecord:true with hostnames when a PTR record exists", async () => {
    const resolver: DnsResolver = {
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => ["dns.google"],
    };
    const result = await reverseLookupIp("8.8.8.8", { resolver });
    expect(result.hasReverseRecord).toBe(true);
    expect(result.hostnames).toEqual(["dns.google"]);
  });

  it("returns hasReverseRecord:false (not an error) when there is confirmed no PTR record", async () => {
    const resolver: DnsResolver = {
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => {
        throw notFoundError();
      },
    };
    const result = await reverseLookupIp("192.0.2.1", { resolver });
    expect(result.hasReverseRecord).toBe(false);
  });

  it("throws on a genuine resolver error (not NXDOMAIN)", async () => {
    const timeoutErr = new Error("queryPtr ETIMEOUT") as NodeJS.ErrnoException;
    timeoutErr.code = "ETIMEOUT";
    const resolver: DnsResolver = {
      resolve4: async () => [],
      resolve6: async () => [],
      reverse: async () => {
        throw timeoutErr;
      },
    };
    await expect(reverseLookupIp("192.0.2.1", { resolver })).rejects.toThrow(/ETIMEOUT/);
  });
});

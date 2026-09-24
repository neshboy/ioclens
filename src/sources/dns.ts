import { promises as nodeDns } from "node:dns";

/**
 * The subset of `node:dns/promises` IOCLens uses, expressed as an interface
 * so tests can inject a fake resolver instead of touching the real network -
 * same dependency-injection shape used for the HTTP-based sources.
 */
export interface DnsResolver {
  resolve4(hostname: string): Promise<string[]>;
  resolve6(hostname: string): Promise<string[]>;
  reverse(ip: string): Promise<string[]>;
}

export const nodeDnsResolver: DnsResolver = {
  resolve4: (hostname) => nodeDns.resolve4(hostname),
  resolve6: (hostname) => nodeDns.resolve6(hostname),
  reverse: (ip) => nodeDns.reverse(ip),
};

export interface DnsClientOptions {
  resolver?: DnsResolver;
}

export interface DomainDnsSummary {
  domain: string;
  resolves: boolean;
  addresses: string[];
}

export interface IpDnsSummary {
  ip: string;
  hasReverseRecord: boolean;
  hostnames: string[];
}

function isNotFoundError(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return code === "ENOTFOUND" || code === "ENODATA" || code === "NXDOMAIN";
}

/**
 * Resolve a domain's A and AAAA records. A domain that fails to resolve at
 * all (confirmed NXDOMAIN/no records on both record types) is not
 * necessarily malicious - it could be parked, sinkholed, or simply not live
 * yet - but it's a real, distinct signal worth surfacing. A genuine resolver
 * error (timeout, network failure) is NOT the same thing as a confirmed
 * non-resolution, so it's thrown (like every other source's failures) rather
 * than silently reported as "doesn't resolve".
 */
export async function resolveDomain(domain: string, options?: DnsClientOptions): Promise<DomainDnsSummary> {
  const resolver = options?.resolver ?? nodeDnsResolver;
  const addresses: string[] = [];
  let realError: unknown;

  try {
    addresses.push(...(await resolver.resolve4(domain)));
  } catch (err) {
    if (!isNotFoundError(err)) realError = err;
  }

  try {
    addresses.push(...(await resolver.resolve6(domain)));
  } catch (err) {
    if (!isNotFoundError(err)) realError ??= err;
  }

  if (addresses.length > 0) {
    return { domain, resolves: true, addresses };
  }

  if (realError) {
    const reason = realError instanceof Error ? realError.message : String(realError);
    throw new Error(`DNS resolution for ${domain} failed: ${reason}`);
  }

  // Both record types confirmed NXDOMAIN/empty - a genuine finding, not a failure.
  return { domain, resolves: false, addresses: [] };
}

/**
 * Reverse-resolve an IP to hostnames (PTR record). Absence of a PTR record
 * is common for legitimate hosts too, so this is treated as a weak,
 * informational signal rather than a strong risk indicator. As with
 * `resolveDomain`, a genuine resolver error is thrown rather than reported
 * as a confirmed "no PTR record".
 */
export async function reverseLookupIp(ip: string, options?: DnsClientOptions): Promise<IpDnsSummary> {
  const resolver = options?.resolver ?? nodeDnsResolver;
  try {
    const hostnames = await resolver.reverse(ip);
    return { ip, hasReverseRecord: hostnames.length > 0, hostnames };
  } catch (err) {
    if (isNotFoundError(err)) {
      return { ip, hasReverseRecord: false, hostnames: [] };
    }
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`Reverse DNS lookup for ${ip} failed: ${reason}`);
  }
}

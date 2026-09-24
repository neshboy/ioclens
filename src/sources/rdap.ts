const RDAP_ORG_BASE = "https://rdap.org";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_USER_AGENT = "ioclens/0.1 (+https://github.com/) - IOC enrichment engine, RDAP lookup";

export interface RdapClientOptions {
  /** Injectable fetch implementation, primarily for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  userAgent?: string;
  /** Override the RDAP bootstrap base, mainly for tests. Defaults to https://rdap.org. */
  baseUrl?: string;
}

type ResolvedOptions = Required<RdapClientOptions>;

function resolveOptions(options?: RdapClientOptions): ResolvedOptions {
  return {
    fetchImpl: options?.fetchImpl ?? fetch,
    timeoutMs: options?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    userAgent: options?.userAgent ?? DEFAULT_USER_AGENT,
    baseUrl: options?.baseUrl ?? RDAP_ORG_BASE,
  };
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapVcardEntry {
  0: string;
  1: Record<string, unknown>;
  2: string;
  3: unknown;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: ["vcard", RdapVcardEntry[]];
  entities?: RdapEntity[];
}

/** Raw shape of an RDAP domain response, trimmed to the fields IOCLens reads. */
export interface RdapDomainResponse {
  objectClassName?: string;
  ldhName?: string;
  handle?: string;
  status?: string[];
  events?: RdapEvent[];
  entities?: RdapEntity[];
  nameservers?: Array<{ ldhName?: string }>;
  secureDNS?: { delegationSigned?: boolean };
  errorCode?: number;
  title?: string;
}

/** Raw shape of an RDAP IP-network response, trimmed to the fields IOCLens reads. */
export interface RdapIpResponse {
  objectClassName?: string;
  handle?: string;
  startAddress?: string;
  endAddress?: string;
  name?: string;
  type?: string;
  country?: string;
  events?: RdapEvent[];
  entities?: RdapEntity[];
  cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>;
  errorCode?: number;
  title?: string;
}

/** Normalized domain registration summary IOCLens scores on. */
export interface RdapDomainSummary {
  domain: string;
  found: boolean;
  registrationDate?: string;
  expirationDate?: string;
  lastChangedDate?: string;
  registrarName?: string;
  status: string[];
}

/** Normalized IP allocation summary IOCLens uses for context (not scored on directly). */
export interface RdapIpSummary {
  ip: string;
  found: boolean;
  networkName?: string;
  networkType?: string;
  country?: string;
  cidr?: string;
  organization?: string;
}

function findEventDate(events: RdapEvent[] | undefined, action: string): string | undefined {
  return events?.find((e) => e.eventAction === action)?.eventDate;
}

function findEntityFullName(entities: RdapEntity[] | undefined, role: string): string | undefined {
  if (!entities) return undefined;
  for (const entity of entities) {
    if (entity.roles?.includes(role) && entity.vcardArray) {
      const [, fields] = entity.vcardArray;
      const fn = fields.find((f) => f[0] === "fn");
      if (fn && typeof fn[3] === "string" && fn[3]) return fn[3];
    }
    const nested = findEntityFullName(entity.entities, role);
    if (nested) return nested;
  }
  return undefined;
}

async function fetchRdap<T>(url: string, opts: ResolvedOptions): Promise<T | { notFound: true }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
  let response: Response;
  try {
    response = await opts.fetchImpl(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": opts.userAgent,
        Accept: "application/rdap+json, application/json",
      },
      redirect: "follow",
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`RDAP request to ${url} failed: ${reason}`);
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 404) {
    return { notFound: true };
  }
  if (!response.ok) {
    throw new Error(`RDAP request to ${url} returned HTTP ${response.status}`);
  }

  const text = await response.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`RDAP request to ${url} returned a non-JSON response`);
  }
}

/**
 * Look up domain registration data via RDAP, bootstrapped through rdap.org
 * (which redirects to the correct registry RDAP server for the domain's
 * TLD, e.g. rdap.verisign.com for .com). No API key required.
 */
export async function queryDomainRdap(domain: string, options?: RdapClientOptions): Promise<RdapDomainSummary> {
  const opts = resolveOptions(options);
  const url = `${opts.baseUrl}/domain/${encodeURIComponent(domain)}`;
  const result = await fetchRdap<RdapDomainResponse>(url, opts);

  if ("notFound" in result) {
    return { domain, found: false, status: [] };
  }

  return {
    domain,
    found: true,
    registrationDate: findEventDate(result.events, "registration"),
    expirationDate: findEventDate(result.events, "expiration"),
    lastChangedDate: findEventDate(result.events, "last changed"),
    registrarName: findEntityFullName(result.entities, "registrar"),
    status: result.status ?? [],
  };
}

/**
 * Look up IP allocation/network data via RDAP, bootstrapped through
 * rdap.org (which redirects to the correct RIR RDAP server, e.g.
 * rdap.arin.net for ARIN-allocated space). No API key required.
 */
export async function queryIpRdap(ip: string, options?: RdapClientOptions): Promise<RdapIpSummary> {
  const opts = resolveOptions(options);
  const url = `${opts.baseUrl}/ip/${encodeURIComponent(ip)}`;
  const result = await fetchRdap<RdapIpResponse>(url, opts);

  if ("notFound" in result) {
    return { ip, found: false };
  }

  const cidrEntry = result.cidr0_cidrs?.[0];
  const cidr = cidrEntry ? `${cidrEntry.v4prefix ?? cidrEntry.v6prefix}/${cidrEntry.length}` : undefined;

  return {
    ip,
    found: true,
    networkName: result.name,
    networkType: result.type,
    country: result.country,
    cidr,
    organization: findEntityFullName(result.entities, "registrant") ?? findEntityFullName(result.entities, "administrative"),
  };
}

# IOCLens

IOCLens is a self-hostable **IOC (Indicator of Compromise) enrichment
engine**. Give it an IP address, a domain, or a file hash, and it
cross-references that one indicator against several **real, free, open
OSINT sources in a single pass** and hands back **one scored, explained
verdict** - instead of five browser tabs of raw feed output you have to
manually correlate yourself.

## The problem

Doing basic IOC triage by hand usually looks like: paste the IP into an
RDAP/WHOIS lookup, paste the domain into crt.sh, check a couple of
blocklists, maybe run `dig`, and then mentally combine all of that into
"is this worth escalating?" Every step is free and public - there's no
secret sauce - but doing it by hand for every indicator that crosses your
desk is slow and inconsistent between analysts. IOCLens automates exactly
that correlation step, with a fully deterministic (no ML, no black box)
scoring model so the same indicator always gets the same verdict for the
same reasons.

## Install / quick start

```bash
git clone <this-repo>
cd ioclens
npm install
npm run build

node dist/cli.js check github.com
node dist/cli.js check 8.8.8.8
node dist/cli.js check d41d8cd98f00b204e9800998ecf8427e
```

Or during development, skip the build step:

```bash
npm run dev -- check github.com
```

### `ioclens check <indicator>`

Auto-detects whether the indicator is an IPv4/IPv6 address, a domain name,
or an MD5/SHA1/SHA256 hash, runs every applicable real OSINT source in
parallel, and prints one report.

Add `--json` for the full machine-readable result (all signals, all raw
source statuses/timings, full reasoning) instead of the human-readable
report.

## Real example output

These are **real, unedited runs** against the live sources (see
`scripts/live-check.mts`), captured during development:

```
$ node dist/cli.js check 1.10.16.5
IOCLens report for 1.10.16.5
  type:      ip (IPv4)
  verdict:   HIGH-RISK  (score: 50/100)
  checked:   2026-09-24T18:20:11.000Z

Sources queried:
  - ip-lists   ok (11457ms)
  - dns        ok (34ms)
  - rdap       ok (301ms)

Reasoning:
  [+50] IP falls within a Spamhaus DROP netblock (1.10.16.0/20, SBL256894) - an authoritative list of netblocks controlled by spammers/malware operators.
  IP is not on blocklist.de's aggregated abuse-report list.
  IP is not a currently-listed Tor exit node.
  IP has no reverse DNS (PTR) record. Common on legitimate hosts too; informational only.
  Network: CHINANET-GD, Chinanet Hostmaster, CN (1.10.16.0/20).
```

`1.10.16.5` is a real address inside a netblock that is, right now, listed
on Spamhaus's live DROP feed - this is a genuine positive detection against
a real, current, third-party list, not a fixture.

```
$ node dist/cli.js check github.com
IOCLens report for github.com
  type:      domain
  verdict:   LOW-RISK  (score: 10/100)

Reasoning:
  Domain was registered 6924 days ago (2007-10-09T18:20:50Z) - established domain, no age-based risk added.
  [+10] 1202 certificate(s) logged from 38 distinct issuing CAs - unusually high churn for one domain.
  Domain resolves to 1 address(es) (20.205.243.166).
```

This one is a genuinely useful, honest example of a **false-positive-prone
heuristic firing correctly but misleadingly**: github.com's cert-issuer-churn
count is real (crt.sh really does log 1200+ certificates across dozens of
issuers for it), but the reason is GitHub's own operational scale, not
malicious activity. See [Limitations](#limitations).

```
$ node dist/cli.js check d41d8cd98f00b204e9800998ecf8427e
IOCLens report for d41d8cd98f00b204e9800998ecf8427e
  type:      hash (MD5)
  verdict:   INSUFFICIENT-DATA

Reasoning:
  No free, no-API-key hash-reputation OSINT source is integrated (researched: MalwareBazaar/URLhaus now require a registered Auth-Key - see README Limitations). Detected as MD5 by length only; no reputation lookup was performed.
```

## Real sources integrated

All of these are queried with real HTTP requests / real DNS resolution
during `ioclens check` - none are mocked in the shipped CLI (mocking only
happens inside the offline test suite, via dependency injection - see
Development below).

| Source | Used for | Notes |
|---|---|---|
| [crt.sh](https://crt.sh/) | Domains | Certificate Transparency log search (Sectigo). Free, no key. **Genuinely slow/flaky** - see Limitations. |
| [RDAP via rdap.org](https://rdap.org/) | Domains + IPs | Bootstraps to the correct registry RDAP server (e.g. `rdap.verisign.com` for `.com`, `rdap.arin.net` for ARIN space). Free, no key, the modern successor to WHOIS. |
| DNS resolution (`node:dns`) | Domains + IPs | Real A/AAAA resolution for domains, PTR (reverse) lookup for IPs. |
| [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) | IPs | Authoritative list of netblocks hijacked/leased for spam and malware hosting. Plain-text CIDR list, free, no key. |
| [blocklist.de](https://lists.blocklist.de/lists/all.txt) | IPs | Aggregated fail2ban-style community abuse reports (brute force, scanning, etc). Plain-text IP list, free, no key. |
| [Tor bulk exit list](https://check.torproject.org/torbulkexitlist) | IPs | Official list of currently-active Tor exit nodes, published by the Tor Project itself. Free, no key. Informational only - Tor usage isn't inherently malicious. |

## Researched but skipped (honestly)

- **abuse.ch (MalwareBazaar / URLhaus / ThreatFox)** - these used to be
  queryable without a key. **Verified during this build** that they now
  return `HTTP 401 {"error":"Unauthorized"}` on every endpoint tested
  without a registered `Auth-Key` (abuse.ch tightened this policy; the key
  itself is free to request, but requires registration, which is out of
  scope for "no API key required"). This is the reason **file hashes get
  no reputation lookup at all** in this version - IOCLens will not fake a
  response from a source it can't actually reach for free.
- **VirusTotal, Shodan, AbuseIPDB, Google Safe Browsing** - all require a
  registered API key even on their free tiers. Not integrated.
- **Spamhaus DROPv6** - the IPv6 equivalent of DROP exists and is free, but
  wasn't integrated in this version; IOCLens's CIDR matcher is IPv4-only
  for now (see Limitations).
- **NSRL (NIST's known-file-hash reference set)** - real, free, and no API
  key, but distributed as a multi-gigabyte bulk dataset meant for offline
  ingestion, not a live per-query lookup - a poor fit for this CLI's
  "one indicator, one request" model. Worth a future local-database mode.

## Scoring

The score is a plain sum of independent, named **signals**, each carrying
a fixed point weight and a human-readable description - there is no
machine learning and no hidden logic. Every point in the final score
traces back to exactly one signal in the `reasoning` output.

**Domains:**

| Signal | Weight | Source |
|---|---|---|
| Registered < 30 days ago | +30 | RDAP |
| Registered 30-89 days ago | +15 | RDAP |
| Registered 90-364 days ago | +5 | RDAP |
| Registered 365+ days ago | 0 | RDAP |
| Latest cert issued < 7 days ago **and** domain < 30 days old | +20 | crt.sh + RDAP |
| 0 certificates logged | +5 | crt.sh |
| Certs logged from 6+ distinct issuing CAs | +10 | crt.sh |
| Domain does not resolve (A/AAAA) | +10 | DNS |

**IPs:**

| Signal | Weight | Source |
|---|---|---|
| In a Spamhaus DROP netblock | +50 | Spamhaus |
| On blocklist.de's abuse list | +25 | blocklist.de |
| Currently a Tor exit node | +10 | Tor Project |
| Reverse DNS / RDAP network context | 0 (informational only) | DNS / RDAP |

Weights are summed, clamped to 0-100, and bucketed deterministically:

- `0` -> **clean**
- `1-24` -> **low-risk**
- `25-49` -> **suspicious**
- `50+` -> **high-risk**
- Every source failed / no OSINT source exists for this indicator type
  (currently: all file hashes) -> **insufficient-data**

A source that errors or times out never gets silently treated as "clean" -
it's recorded as a zero-weight `*-unavailable` signal and shown in the
reasoning, so a degraded run is always visibly degraded, not falsely
reassuring.

## Limitations

- **crt.sh is genuinely slow and occasionally flaky.** In real runs during
  this project's own development, `crtsh` queries took anywhere from ~3s
  to ~16s, and it's known to occasionally return non-JSON (HTML) responses
  under load. IOCLens surfaces that as a degraded/errored source rather
  than crashing the whole check, but a transient failure means the
  certificate signal is skipped for that run. (This matches this author's
  sibling project `certwatch`'s independent finding of the same behavior.)
- **The Tor exit-node check intermittently times out.** During development,
  a direct request to `check.torproject.org` failed with a 10s connect
  timeout on one attempt and succeeded immediately on the next, from the
  same machine/network. IOCLens tolerates this (the Tor signal is simply
  marked unavailable for that run, and the rest of the check proceeds) but
  it means Tor exit-node coverage can be silently incomplete on any given
  run.
- **No hash reputation source at all.** As documented above, no genuinely
  free, no-API-key hash-reputation OSINT source could be found - abuse.ch's
  APIs now require a registered Auth-Key. `check` on a hash only classifies
  the algorithm (MD5/SHA1/SHA256) by length; it performs zero network
  requests and always returns `insufficient-data`.
- **IPv4-only IP blocklists.** Spamhaus DROP (IPv4) is integrated; DROPv6
  is not. An IPv6 indicator still gets RDAP + reverse DNS, but no blocklist
  cross-reference.
- **No persistent caching.** Every `check` on an IP re-downloads the full
  Spamhaus DROP (~1,700 entries), blocklist.de (~32,000 IPs), and Tor exit
  lists from scratch. That's fine for occasional interactive use but would
  be wasteful/slow for high-volume batch scanning - a future version should
  cache these lists locally with a TTL.
- **The certificate-issuer-churn heuristic is a real false-positive risk on
  large legitimate operators.** As shown in the `github.com` example above,
  a domain serving many subdomains/edge nodes will legitimately accumulate
  hundreds of certificates from multiple CAs - the signal fires as designed,
  but "unusual for one domain" doesn't distinguish "hyperscale legitimate
  infrastructure" from "certificate churn on disposable phishing infra."
  Human review of any non-clean verdict is still necessary.
- **Domain parsing is a simplified regex**, not a full RFC 1035 / public
  suffix list parser, and has no IDN/punycode homograph handling.
- **This is a heuristic triage aid, not a certified detection engine.**
  A high-risk verdict means "several real signals point this way, worth a
  human look" - not proof of compromise. A clean/low-risk verdict means
  "these particular checks came back unremarkable," not "guaranteed safe."

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run build        # compile to dist/
```

`npm test` is fully deterministic and offline: every OSINT client (crt.sh,
RDAP, DNS, IP blocklists) is built around an injectable `fetch`/resolver
function, and the test suite exercises them entirely against mocked
responses - no network access required.

To check real connectivity against the live sources using the actual
IOCLens pipeline (not curl), run the small manual script (not part of
`npm test`, since network access isn't guaranteed in every environment):

```bash
npx tsx scripts/live-check.mts github.com 8.8.8.8 1.10.16.5
```

## License

MIT - see [LICENSE](./LICENSE).

import { isIPv4, isIPv6 } from "node:net";
import type { DetectedIndicator, HashAlgorithm } from "./types.js";

const HASH_RE = /^[a-fA-F0-9]+$/;
// A domain label: alnum, hyphens allowed but not leading/trailing. At least one dot,
// TLD must be alphabetic and 2+ chars. Intentionally simple - not a full RFC 1035 parser.
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,}$/i;

function hashAlgorithmForLength(length: number): HashAlgorithm | undefined {
  switch (length) {
    case 32:
      return "md5";
    case 40:
      return "sha1";
    case 64:
      return "sha256";
    default:
      return undefined;
  }
}

/**
 * Classify a raw user-supplied indicator string as an IP address, domain name,
 * or file hash (MD5/SHA1/SHA256 by length+charset). Throws on input that
 * doesn't match any recognized indicator shape.
 */
export function detectIndicator(raw: string): DetectedIndicator {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Empty indicator: expected an IP address, domain name, or file hash.");
  }

  // IP classification is delegated to node:net's isIPv4/isIPv6 rather than
  // hand-rolled regexes - it already correctly rejects things like leading
  // zero octets ("192.168.01.1") and handles every valid "::" compression
  // placement in IPv6, which a simple regex gets wrong.
  if (isIPv4(trimmed)) {
    return { raw, value: trimmed, type: "ip", ipVersion: 4 };
  }

  if (isIPv6(trimmed)) {
    return { raw, value: trimmed.toLowerCase(), type: "ip", ipVersion: 6 };
  }

  if (HASH_RE.test(trimmed)) {
    const algo = hashAlgorithmForLength(trimmed.length);
    if (algo) {
      return { raw, value: trimmed.toLowerCase(), type: "hash", hashAlgorithm: algo };
    }
    // Falls through: an all-hex string of an unrecognized length is not a
    // supported hash and is not a domain either (no dots) - reject below.
  }

  if (DOMAIN_RE.test(trimmed)) {
    return { raw, value: trimmed.toLowerCase(), type: "domain" };
  }

  throw new Error(
    `Unrecognized indicator "${raw}": expected an IPv4/IPv6 address, a domain name, or an MD5/SHA1/SHA256 hash (32/40/64 hex chars).`,
  );
}

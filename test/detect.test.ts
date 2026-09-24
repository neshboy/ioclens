import { describe, expect, it } from "vitest";
import { detectIndicator } from "../src/detect.js";

describe("detectIndicator", () => {
  it("detects a valid IPv4 address", () => {
    const result = detectIndicator("8.8.8.8");
    expect(result.type).toBe("ip");
    expect(result.ipVersion).toBe(4);
    expect(result.value).toBe("8.8.8.8");
  });

  it("rejects an IPv4-shaped string with an out-of-range octet", () => {
    expect(() => detectIndicator("999.1.1.1")).toThrow();
  });

  it("rejects an IPv4-shaped string with a leading-zero octet", () => {
    expect(() => detectIndicator("192.168.01.1")).toThrow();
  });

  it("detects a valid IPv6 address (compressed form)", () => {
    const result = detectIndicator("2001:4860:4860::8888");
    expect(result.type).toBe("ip");
    expect(result.ipVersion).toBe(6);
  });

  it("detects a domain name and lowercases it", () => {
    const result = detectIndicator("Example.COM");
    expect(result.type).toBe("domain");
    expect(result.value).toBe("example.com");
  });

  it("detects a subdomain", () => {
    const result = detectIndicator("mail.example.co.uk");
    expect(result.type).toBe("domain");
  });

  it("detects an MD5 hash by length", () => {
    const result = detectIndicator("d41d8cd98f00b204e9800998ecf8427e");
    expect(result.type).toBe("hash");
    expect(result.hashAlgorithm).toBe("md5");
  });

  it("detects a SHA1 hash by length", () => {
    const result = detectIndicator("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect(result.type).toBe("hash");
    expect(result.hashAlgorithm).toBe("sha1");
  });

  it("detects a SHA256 hash by length (the real SHA256 of an empty input, 64 hex chars)", () => {
    const sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(sha256).toHaveLength(64);
    const result = detectIndicator(sha256);
    expect(result.type).toBe("hash");
    expect(result.hashAlgorithm).toBe("sha256");
  });

  it("rejects a 65-char hex string (not a supported hash length, no dots)", () => {
    const tooLong = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855f";
    expect(tooLong).toHaveLength(65);
    expect(() => detectIndicator(tooLong)).toThrow(/Unrecognized indicator/);
  });

  it("normalizes hash case to lowercase", () => {
    const result = detectIndicator("D41D8CD98F00B204E9800998ECF8427E");
    expect(result.value).toBe("d41d8cd98f00b204e9800998ecf8427e");
  });

  it("rejects an all-hex string of an unsupported hash length with no dots", () => {
    expect(() => detectIndicator("abcdef1234567890")).toThrow(/Unrecognized indicator/);
  });

  it("rejects empty input", () => {
    expect(() => detectIndicator("   ")).toThrow(/Empty indicator/);
  });

  it("rejects garbage input that matches nothing", () => {
    expect(() => detectIndicator("not a valid !!! indicator")).toThrow(/Unrecognized indicator/);
  });
});

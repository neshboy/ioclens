// Manual, one-off live smoke test against the real OSINT sources using the
// actual IOCLens enrichment pipeline (not curl) - crt.sh, RDAP (via
// rdap.org), real DNS resolution, and the real Spamhaus DROP / blocklist.de
// / Tor exit-node lists. Not part of the automated test suite (network
// access is not guaranteed in CI/sandboxes), but useful to run by hand to
// confirm real connectivity. See README "Development" notes.
import { enrich } from "../src/enrich.js";

const targets = process.argv.slice(2);
const defaultTargets = ["github.com", "8.8.8.8", "d41d8cd98f00b204e9800998ecf8427e"];
const indicators = targets.length > 0 ? targets : defaultTargets;

for (const indicator of indicators) {
  const started = Date.now();
  console.log(`\n=== ${indicator} ===`);
  try {
    const result = await enrich(indicator);
    console.log(`verdict: ${result.verdict} (score: ${result.score}) in ${Date.now() - started}ms`);
    for (const s of result.sources) {
      console.log(`  source ${s.source}: ${s.status}${s.durationMs !== undefined ? ` (${s.durationMs}ms)` : ""}${s.error ? ` - ${s.error}` : ""}`);
    }
    console.log("  reasoning:");
    for (const line of result.reasoning) {
      console.log(`    ${line}`);
    }
  } catch (err) {
    console.error(`FAILED after ${Date.now() - started}ms:`, (err as Error).message);
    process.exitCode = 1;
  }
}

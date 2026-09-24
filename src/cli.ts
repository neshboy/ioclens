#!/usr/bin/env node
import { Command } from "commander";
import { enrich } from "./enrich.js";
import type { EnrichmentResult } from "./types.js";

const program = new Command();

program
  .name("ioclens")
  .description(
    "Self-hostable IOC enrichment engine: cross-references an IP, domain, or file hash against real open OSINT sources and returns one scored, explained verdict.",
  )
  .version("0.1.0");

program
  .command("check <indicator>")
  .description("Enrich one indicator (IP, domain, or file hash - auto-detected) against real OSINT sources")
  .option("--json", "output the full result as JSON instead of a human-readable report")
  .action(async (indicator: string, opts: { json?: boolean }) => {
    let result: EnrichmentResult;
    try {
      result = await enrich(indicator);
    } catch (err) {
      console.error(err instanceof Error ? err.message : err);
      process.exitCode = 1;
      return;
    }

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    printHumanReadable(result);
  });

function printHumanReadable(result: EnrichmentResult): void {
  const { indicator, verdict, score, reasoning, sources } = result;

  console.log(`IOCLens report for ${indicator.raw}`);
  console.log(`  type:      ${indicator.type}${indicator.ipVersion ? ` (IPv${indicator.ipVersion})` : ""}${indicator.hashAlgorithm ? ` (${indicator.hashAlgorithm.toUpperCase()})` : ""}`);
  console.log(`  verdict:   ${verdict.toUpperCase()}${verdict === "insufficient-data" ? "" : `  (score: ${score}/100)`}`);
  console.log(`  checked:   ${result.checkedAt}`);
  console.log();

  if (sources.length > 0) {
    console.log("Sources queried:");
    for (const s of sources) {
      const timing = s.durationMs !== undefined ? ` (${s.durationMs}ms)` : "";
      console.log(`  - ${s.source.padEnd(10)} ${s.status}${timing}${s.status === "error" ? ` - ${s.error}` : ""}`);
    }
    console.log();
  }

  console.log("Reasoning:");
  for (const line of reasoning) {
    console.log(`  ${line}`);
  }
}

program.parseAsync(process.argv).catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});

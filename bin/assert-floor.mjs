#!/usr/bin/env node
/**
 * Regression gate: assert a measured tool meets a minimum weighted coverage and has zero false
 * positives. Reads results/<tool>.json (produced by bin/run.mjs) and exits non-zero if the tool
 * regressed — so CI fails a change that lowers coverage or introduces a false positive.
 *
 * Usage:  node bin/assert-floor.mjs [tool] [floor]
 *   tool  — adapter name (default: mcp-bastion)
 *   floor — minimum RobustCoverage out of the vector count (default: env BENCH_FLOOR or 13.0)
 *
 * Gate metric = RobustCoverage (mean detection across a vector's fixtures), matching the leaderboard
 * headline. Older result files without robustCoverage fall back to enforce * 1.0 + detect * 0.5.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const tool = process.argv[2] ?? "mcp-bastion";
const floor = Number(process.argv[3] ?? process.env.BENCH_FLOOR ?? "13.0");

const resultsPath = join(root, "results", `${tool}.json`);
let summary;
try {
  summary = JSON.parse(readFileSync(resultsPath, "utf8")).summary;
} catch (e) {
  console.error(`✗ could not read ${resultsPath}: ${e.message}`);
  console.error(`  run \`node bin/run.mjs ${tool}\` first.`);
  process.exit(2);
}

const { enforce = 0, detect = 0 } = summary.covered ?? {};
// Gate on RobustCoverage (headline). Fall back to enforce+detect/2 for pre-fix result files.
const weighted = typeof summary.robustCoverage === "number" ? summary.robustCoverage : enforce + detect * 0.5;
const fp = summary.falsePositives ?? 0;

const problems = [];
if (weighted < floor) {
  problems.push(`weighted coverage ${weighted.toFixed(1)} is below the floor of ${floor.toFixed(1)}`);
}
if (fp !== 0) {
  problems.push(`${fp} false positive(s) (must be 0)`);
}

const label = `${tool}: RobustCoverage ${weighted.toFixed(1)}/${summary.verifiedVectors}` +
  `${typeof summary.capability === "number" ? `, Capability ${summary.capability.toFixed(1)}` : ""} ` +
  `(enforce ${enforce}, detect ${detect}), false positives ${fp}`;

if (problems.length > 0) {
  console.error(`✗ regression gate FAILED — ${label}`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}

console.log(`✓ regression gate passed — ${label} (floor ${floor.toFixed(1)}).`);

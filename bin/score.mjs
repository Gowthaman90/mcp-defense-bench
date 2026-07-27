#!/usr/bin/env node
/**
 * mcp-defense-bench scorer (skeleton).
 *
 * Joins a tool's coverage (verified results, or self-reported claim as a fallback) against the
 * neutral rubric, and reports coverage rolled up by architectural layer, NIST AI RMF function, and
 * OWASP category.
 *
 * Scoring model (v0):
 *   enforce = 1.0, detect = 0.5, observe = 0.1, none = 0.0
 * A vector's framework-mappings are credited at its coverage weight. This is intentionally simple
 * and will be replaced by testcase-verified results (see testcases/) — a self-reported `enforce`
 * with no passing testcase should NOT count once verification lands.
 *
 * Usage: node bin/score.mjs adapters/mcp-bastion/coverage.json
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const WEIGHT = { enforce: 1.0, detect: 0.5, observe: 0.1, none: 0.0 };

const adapterPath = process.argv[2];
if (!adapterPath) {
  console.error("usage: node bin/score.mjs <adapters/<tool>/coverage.json>");
  process.exit(1);
}

const rubric = JSON.parse(readFileSync(join(root, "rubric", "crosswalk.json"), "utf8"));
const adapter = JSON.parse(readFileSync(resolve(adapterPath), "utf8"));

if (adapter.rubricVersion !== rubric.version) {
  console.warn(
    `⚠️  adapter targets rubric ${adapter.rubricVersion} but rubric is ${rubric.version} — re-verify.`,
  );
}

const add = (obj, key, w) => {
  obj[key] = obj[key] || { covered: 0, total: 0 };
  obj[key].total += 1;
  obj[key].covered += w;
};

const byLayer = {},
  byNist = {},
  byOwaspLlm = {},
  byOwaspAgentic = {};
let covered = 0; // headline = RobustCoverage (mean over a vector's fixtures)
let coveredCapability = 0; // secondary = Capability (best-case)
let unknown = 0;

for (const v of rubric.vectors) {
  const cov = adapter.coverage?.[v.id];
  const level = cov?.level ?? "none";
  if (level === "unknown") unknown += 1;
  // RobustCoverage when available (verified runs); fall back to capability weight for self-reported claims.
  const w = typeof cov?.robustCoverage === "number" ? cov.robustCoverage : (WEIGHT[level] ?? 0);
  const capW = typeof cov?.capability === "number" ? cov.capability : (WEIGHT[level] ?? 0);
  covered += w;
  coveredCapability += capW;
  for (const l of v.mcpLayer) add(byLayer, l, w);
  for (const n of v.nistAiRmf) add(byNist, n, w);
  for (const o of v.owaspLlm2025) add(byOwaspLlm, o, w);
  for (const a of v.owaspAgentic2026) add(byOwaspAgentic, a, w);
}

const pct = (o) =>
  Object.fromEntries(
    Object.entries(o).map(([k, { covered, total }]) => [
      k,
      `${((covered / total) * 100).toFixed(0)}% (${covered.toFixed(1)}/${total})`,
    ]),
  );

const report = {
  tool: adapter.tool,
  class: adapter.class ?? "unknown",
  reproducible: adapter.reproducible ?? false,
  scoreable: (adapter.reproducible ?? false) === true,
  rubricVersion: rubric.version,
  verified: false, // flips true once testcases gate the levels
  unassessedVectors: unknown, // 'unknown' levels — scored as 0 until a testcase assesses them
  metric: "RobustCoverage = mean detection across all fixtures of a vector; Capability = best-case (≥1 fixture)",
  overall: `${((covered / rubric.vectors.length) * 100).toFixed(0)}% (${covered.toFixed(1)}/${rubric.vectors.length} RobustCoverage)`,
  overallCapability: `${((coveredCapability / rubric.vectors.length) * 100).toFixed(0)}% (${coveredCapability.toFixed(1)}/${rubric.vectors.length} best-case)`,
  byLayer: pct(byLayer),
  byNistAiRmf: pct(byNist),
  byOwaspLlm2025: pct(byOwaspLlm),
  byOwaspAgentic2026: pct(byOwaspAgentic),
};

console.log(JSON.stringify(report, null, 2));

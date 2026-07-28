#!/usr/bin/env node
/**
 * Live runner: executes the test-case corpus against one adapter, deriving VERIFIED coverage.
 *
 * For each test case it calls the adapter twice — on the malicious fixture and the benign control —
 * then applies the scoring rule from adapters/CONTRACT.md. Writes:
 *   - results/<tool>.json                    detailed per-testcase log
 *   - adapters/<tool>/coverage.json          coverage updated with verified levels + evidence
 *
 * Usage: node bin/run.mjs <tool>        e.g. node bin/run.mjs mcp-bastion
 */
import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const tool = process.argv[2];
if (!tool) {
  console.error("usage: node bin/run.mjs <tool>   (a directory under adapters/)");
  process.exit(1);
}

const rubric = JSON.parse(readFileSync(join(root, "rubric", "crosswalk.json"), "utf8"));
const rubricIds = rubric.vectors.map((v) => v.id);

// Load every test case.
const tcDir = join(root, "testcases");
const cases = [];
for (const vec of readdirSync(tcDir)) {
  const p = join(tcDir, vec);
  if (!statSync(p).isDirectory() || vec.startsWith("_")) continue;
  for (const f of readdirSync(p).filter((x) => x.endsWith(".json")))
    cases.push(JSON.parse(readFileSync(join(p, f), "utf8")));
}

// Load the adapter.
let adapter;
try {
  adapter = await import(fileURLToPath(new URL(`../adapters/${tool}/adapter.mjs`, import.meta.url)));
} catch (e) {
  console.error(`No runnable adapter at adapters/${tool}/adapter.mjs — ${e.message}`);
  process.exit(1);
}

const levelFrom = (mal, benign) => {
  if (!mal.detect) return { level: "none", falsePositive: false };
  const fp = !!benign.detect;
  if (fp) return { level: "none", falsePositive: true };
  return { level: mal.enforce ? "enforce" : "detect", falsePositive: false };
};

const WEIGHT = { enforce: 1, detect: 0.5, observe: 0.1, none: 0, unknown: 0 };
const rank = { none: 0, detect: 1, enforce: 2 };

const perCase = [];
const byVector = {}; // vector -> { fixtures: [ per-fixture result ] }  (ALL fixtures, not just the best)
for (const tc of cases) {
  const mal = await adapter.assess(tc.fixture, tc);
  const benign = await adapter.assess(tc.benignControl, tc);
  const { level, falsePositive } = levelFrom(mal, benign); // levelFrom already forces level→none on an FP
  const rec = { id: tc.id, level, falsePositive, mal, benign, expected: tc.expected };
  perCase.push(rec);
  (byVector[tc.vector] ||= { fixtures: [] }).fixtures.push({
    id: tc.id,
    level,
    weight: WEIGHT[level] ?? 0, // FP → level none → weight 0, so it drags mean/min down (see #scoring-fix)
    falsePositive,
    evasion: tc.evasion ?? null,
  });
}

/**
 * Per-vector metrics (fix for the max-aggregation defect reported by M. Brighindi, 2026-07-24):
 *   Capability     = max_i w_i   — best-case; "detects ≥1 fixture" (the OLD headline; kept as secondary)
 *   RobustCoverage = mean_i w_i  — reliability across ALL fixtures incl. evasion variants (NEW headline)
 *   Guaranteed     = min_i w_i   — worst-case floor
 * A false positive on any benign variant contributes weight 0, so it penalises this vector's mean and
 * zeroes its guaranteed floor — it can no longer be masked by a clean pass on another variant.
 */
function vectorMetrics(fx) {
  const ws = fx.map((f) => f.weight);
  const best = fx.reduce((a, b) => (rank[b.level] > rank[a.level] ? b : a));
  return {
    level: best.level, // capability level, for glyphs / backward compat
    evidence: best.id,
    capability: Math.max(...ws),
    robustCoverage: Number((ws.reduce((a, b) => a + b, 0) / ws.length).toFixed(4)),
    guaranteed: Math.min(...ws),
    fixtures: fx.length,
    fpCount: fx.filter((f) => f.falsePositive).length,
  };
}

// Build verified coverage across ALL rubric vectors (untested → unknown).
const coverage = {};
for (const id of rubricIds) {
  if (!byVector[id]) {
    coverage[id] = { level: "unknown", capability: 0, robustCoverage: 0, guaranteed: 0, fixtures: 0, fpCount: 0, evidence: null, verified: false };
    continue;
  }
  const m = vectorMetrics(byVector[id].fixtures);
  coverage[id] = {
    level: m.level,
    capability: m.capability,
    robustCoverage: m.robustCoverage,
    guaranteed: m.guaranteed,
    fixtures: m.fixtures,
    fpCount: m.fpCount,
    evidence: m.evidence,
    verified: true,
    ...(m.fpCount ? { falsePositive: true } : {}),
  };
}

// Persist verified coverage.json (preserve adapter metadata).
const covPath = join(root, "adapters", tool, "coverage.json");
let prev = {};
try {
  prev = JSON.parse(readFileSync(covPath, "utf8"));
} catch {
  /* new adapter */
}
const covOut = {
  tool: adapter.meta?.tool ?? tool,
  repo: prev.repo ?? null,
  class: adapter.meta?.class ?? prev.class ?? "unknown",
  reproducible: adapter.meta?.reproducible ?? prev.reproducible ?? false,
  version: prev.version ?? "local",
  rubricVersion: rubric.version,
  measuredBy: "bin/run.mjs",
  coverage,
};
writeFileSync(covPath, JSON.stringify(covOut, null, 2) + "\n");

// Detailed results.
mkdirSync(join(root, "results"), { recursive: true });
const robustWeighted = rubricIds.reduce((a, id) => a + (coverage[id].robustCoverage ?? 0), 0);
const capabilityWeighted = rubricIds.reduce((a, id) => a + (coverage[id].capability ?? 0), 0);
const guaranteedWeighted = rubricIds.reduce((a, id) => a + (coverage[id].guaranteed ?? 0), 0);
const summary = {
  tool: covOut.tool,
  rubricVersion: rubric.version,
  casesRun: cases.length,
  verifiedVectors: Object.values(coverage).filter((c) => c.verified).length,
  falsePositives: perCase.filter((c) => c.falsePositive).length,
  covered: { enforce: 0, detect: 0, none: 0, unknown: 0 },
  // Headline = CorpusRobustCoverage (mean over a vector's fixtures). Capability (best-case) kept as secondary.
  overall: `${((robustWeighted / rubricIds.length) * 100).toFixed(0)}% (${robustWeighted.toFixed(1)}/${rubricIds.length} CorpusRobustCoverage)`,
  robustCoverage: Number(robustWeighted.toFixed(2)),
  capability: Number(capabilityWeighted.toFixed(2)),
  guaranteed: Number(guaranteedWeighted.toFixed(2)),
};
for (const id of rubricIds) summary.covered[coverage[id].level] = (summary.covered[coverage[id].level] ?? 0) + 1;
writeFileSync(join(root, "results", `${tool}.json`), JSON.stringify({ summary, cases: perCase }, null, 2) + "\n");

console.log(JSON.stringify(summary, null, 2));
const brittle = rubricIds.filter((id) => coverage[id].verified && coverage[id].robustCoverage < coverage[id].capability);
if (brittle.length)
  console.log(`  ⚠ evasion-brittle (RobustCoverage < Capability): ${brittle.join(", ")}`);
for (const c of perCase.filter((c) => c.level !== "none" || c.falsePositive))
  console.log(`  ${c.falsePositive ? "⚠ FP" : "✓"} ${c.id} → ${c.level}${c.mal.signal ? "  [" + c.mal.signal + "]" : ""}`);

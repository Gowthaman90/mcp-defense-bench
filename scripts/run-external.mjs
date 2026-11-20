#!/usr/bin/env node
/**
 * External-corpus runner (docs/EXTERNAL-PROTOCOL.md). Runs one adapter module over testcases-external/
 * and applies the scoring rule of adapters/CONTRACT.md:
 *   !detect → none; detect and control detects → none + false positive; detect and enforce → enforce;
 *   detect → detect.
 * A case with no benign control (MCPTox) is scored ungated: its level comes from the fixture alone, and
 * it is marked `gated: false`. A separate runner (rather than bin/run.mjs) lets a frozen build's own
 * adapter (e.g. the bench at 2771b2a for mcp-bastion 1.0.0) be driven over the same converted corpus.
 *
 * Usage: node scripts/run-external.mjs <adapter.mjs> <label> <corpus_dir> <out.json>
 */
import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [adapterPath, label, corpusDir, outPath] = process.argv.slice(2);
if (!outPath) {
  console.error("usage: node scripts/run-external.mjs <adapter.mjs> <label> <corpus_dir> <out.json>");
  process.exit(1);
}
const adapter = await import(pathToFileURL(resolve(adapterPath)).href);

const cases = [];
for (const vec of readdirSync(corpusDir).sort()) {
  const p = join(corpusDir, vec);
  if (!statSync(p).isDirectory()) continue;
  for (const f of readdirSync(p).filter((x) => x.endsWith(".json")).sort()) cases.push(JSON.parse(readFileSync(join(p, f), "utf8")));
}

const wired = (tc) =>
  (!Array.isArray(adapter.meta?.fixtureTypes) || adapter.meta.fixtureTypes.includes(tc.fixture?.type)) &&
  !(Array.isArray(adapter.meta?.unwiredFixtureTypes) && adapter.meta.unwiredFixtureTypes.includes(tc.fixture?.type));
const WEIGHT = { enforce: 1, detect: 0.5, none: 0 };
const startedAt = new Date().toISOString();
const perCase = [];
for (const tc of cases) {
  if (!wired(tc)) { perCase.push({ id: tc.id, vector: tc.vector, external: tc.external, wired: false }); continue; }
  const mal = await adapter.assess(tc.fixture, tc);
  const gated = !!tc.benignControl;
  const benign = gated ? await adapter.assess(tc.benignControl, tc) : null;
  let level = "none", falsePositive = false;
  if (mal?.detect) {
    if (gated && benign?.detect) falsePositive = true;
    else level = mal.enforce ? "enforce" : "detect";
  }
  perCase.push({ id: tc.id, vector: tc.vector, external: tc.external, wired: true, gated, level, weight: WEIGHT[level],
    falsePositive, mal: { detect: !!mal?.detect, enforce: !!mal?.enforce, signal: mal?.signal ?? null },
    benign: benign ? { detect: !!benign.detect, enforce: !!benign.enforce, signal: benign.signal ?? null } : null });
}
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify({ label, adapter: adapterPath, startedAt, finishedAt: new Date().toISOString(),
  casesRun: perCase.filter((c) => c.wired).length, notWired: perCase.filter((c) => !c.wired).length, cases: perCase }, null, 1) + "\n");
console.log(`${label}: ${perCase.length} cases (${perCase.filter((c) => !c.wired).length} not wired) → ${outPath}`);
